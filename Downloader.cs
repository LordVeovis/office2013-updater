/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
using Kveer.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Kveer.Office2013Updater
{
	[Flags]
	enum Platform
	{
		X86 = 1,
		X64 = 2
	}
	class Downloader
	{
		public string WorkingDirectory { get; set; }
		public string UpdateList { get; set; }
		public string SourceDirectory { get; set; }

		Platform _targetPlatform;
		Platform _updateSourcePlatform;
		bool _initialized;

		public void Download()
		{

		}

		void Initialize()
		{
			if (_initialized)
				throw new ApplicationException("Already initialized !");

			if (!Directory.Exists(SourceDirectory))
				throw new ApplicationException("The specified source directory does not exists");

			if (!File.Exists(UpdateList))
				throw new ApplicationException("The specified update source file does not exists");

			if (!Directory.Exists(WorkingDirectory))
				Directory.CreateDirectory(WorkingDirectory);

			if (Directory.Exists(Path.Combine(SourceDirectory, "x64")))
				_targetPlatform |= Platform.X86;

			if (Directory.Exists(Path.Combine(SourceDirectory, "x86")))
				_targetPlatform |= Platform.X64;

			_initialized = true;
		}

		public async Task DownloadAllFiles()
		{
			if (!_initialized)
				Initialize();

			var xdoc = XDocument.Load("file:///" + UpdateList);
			_updateSourcePlatform = (Platform)Enum.Parse(typeof(Platform), xdoc.Root.Attribute("platform").Value, true);
			var files = from el in xdoc.Root.Elements("update")
						select el.Attribute("uri").Value;

			Console.WriteLine("Starting downloads in {0}...", WorkingDirectory);
			//Parallel.ForEach(files, async (s) => await DownloadFile(s));
			await files.ForEachAsync(3, (s) => DownloadFile(s));

			Console.WriteLine("Starting extraction...");
			Parallel.ForEach(Directory.GetFiles(WorkingDirectory, "*.exe"), (f) => Extract(f));
		}

		async Task DownloadFile(string source, bool force = false)
		{
			Contract.Requires<ArgumentNullException>(source != null);

			Console.WriteLine("Downloading {0}...", source);

			var destination = Path.Combine(WorkingDirectory, Path.GetFileName(source));
			if (!FileExistsAndIsValid(destination) || force)
			{
				var uri = new Uri(source);

				WebClient client = new WebClient();

				await client.DownloadFileTaskAsync(source, destination);
			}
		}

		bool FileExistsAndIsValid(string file)
		{
			if (!File.Exists(file))
				return false;

			if (GetSigncodeDate(file) == null)
				return false;

			return true;
		}

		void Extract(string filename)
		{
			Contract.Requires<ArgumentNullException>(filename != null);

			var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("D"));
			var date = GetSigncodeDate(filename);

			Console.WriteLine("Extracting {0} in {1}...", filename, tmpDir);
			Process p = new Process();
			p.StartInfo = new ProcessStartInfo(filename, string.Format("/extract:{0} /passive", tmpDir));
			p.Start();
			p.WaitForExit();

			foreach (var file in Directory.GetFiles(tmpDir, "*.msp"))
			{
				var newName = string.Format("{0:yyyy-MM-dd-HHmmss}-{1}", date, Path.GetFileName(file));
				var newPath = Path.Combine(SourceDirectory, _updateSourcePlatform.ToString(), "updates", newName);

				if (File.Exists(newPath))
					File.Delete(newPath);

				File.Move(file, newPath);
			}

			Directory.Delete(tmpDir, true);
		}

		/// <summary>
		/// http://stackoverflow.com/questions/3281057/get-timestamp-from-authenticode-signed-files-in-net
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		static DateTime? GetSigncodeDate(string filename)
		{
			try
			{
				int encodingType;
				int contentType;
				int formatType;
				IntPtr certStore = IntPtr.Zero;
				IntPtr cryptMsg = IntPtr.Zero;
				IntPtr context = IntPtr.Zero;

				if (!WinCrypt.CryptQueryObject(
					WinCrypt.CERT_QUERY_OBJECT_FILE,
					Marshal.StringToHGlobalUni(filename),
					WinCrypt.CERT_QUERY_CONTENT_FLAG_ALL,
					WinCrypt.CERT_QUERY_FORMAT_FLAG_ALL,
					0,
					out encodingType,
					out contentType,
					out formatType,
					ref certStore,
					ref cryptMsg,
					ref context))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				//expecting contentType=10; CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED 
				//Logger.LogInfo(string.Format("Querying file '{0}':", filename));
				//Logger.LogInfo(string.Format("  Encoding Type: {0}", encodingType));
				//Logger.LogInfo(string.Format("  Content Type: {0}", contentType));
				//Logger.LogInfo(string.Format("  Format Type: {0}", formatType));
				//Logger.LogInfo(string.Format("  Cert Store: {0}", certStore.ToInt32()));
				//Logger.LogInfo(string.Format("  Crypt Msg: {0}", cryptMsg.ToInt32()));
				//Logger.LogInfo(string.Format("  Context: {0}", context.ToInt32()));


				// Get size of the encoded message.
				int cbData = 0;
				if (!WinCrypt.CryptMsgGetParam(
					cryptMsg,
					WinCrypt.CMSG_ENCODED_MESSAGE,//Crypt32.CMSG_SIGNER_INFO_PARAM,
					0,
					IntPtr.Zero,
					ref cbData))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				var vData = new byte[cbData];

				// Get the encoded message.
				if (!WinCrypt.CryptMsgGetParam(
					cryptMsg,
					WinCrypt.CMSG_ENCODED_MESSAGE,//Crypt32.CMSG_SIGNER_INFO_PARAM,
					0,
					vData,
					ref cbData))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				var signedCms = new SignedCms();
				signedCms.Decode(vData);

				try
				{
					signedCms.CheckSignature(true);
				}
				catch (CryptographicException)
				{
					return null;
				}

				foreach (var signerInfo in signedCms.SignerInfos)
				{
					foreach (var unsignedAttribute in signerInfo.UnsignedAttributes)
					{
						if (unsignedAttribute.Oid.Value == WinCrypt.szOID_RSA_counterSign)
						{
							foreach (var counterSignInfo in signerInfo.CounterSignerInfos)
							{
								foreach (var signedAttribute in counterSignInfo.SignedAttributes)
								{
									if (signedAttribute.Oid.Value == WinCrypt.szOID_RSA_signingTime)
									{
										Pkcs9SigningTime signingTime = (Pkcs9SigningTime)signedAttribute.Values[0];
										return signingTime.SigningTime;
									}
								}
							}
						}
					}
				}
			}
			catch (Exception)
			{
				// no logging
			}

			return null;
		}

		string GetFileName(string uri)
		{
			Contract.Requires<ArgumentNullException>(uri != null);

			var match = Regex.Match(@"[a-zA-Z0-9\-_\.]+$", uri);

			return match.Success ? match.Value : null;
		}
	}
}
