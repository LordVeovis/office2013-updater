/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kveer.Office2013Updater
{
	static class Enumerable
	{
		/// <summary>
		/// http://blogs.msdn.com/b/pfxteam/archive/2012/03/05/10278165.aspx
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="source"></param>
		/// <param name="dop"></param>
		/// <param name="body"></param>
		/// <returns></returns>
		public static Task ForEachAsync<T>(this IEnumerable<T> source, int dop, Func<T, Task> body)
		{
			return Task.WhenAll(
				from partition in Partitioner.Create(source).GetPartitions(dop)
				select Task.Run(async delegate
				{
					using (partition)
						while (partition.MoveNext())
							await body(partition.Current);
				}));
		}

	}
}
