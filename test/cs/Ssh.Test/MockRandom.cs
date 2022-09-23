using Microsoft.DevTunnels.Ssh.Algorithms;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

internal class MockRandom : IRandom
{
	private int valueIndex;

	public MockRandom(params Buffer[] values)
	{
		Values.AddRange(values);
	}

	public List<Buffer> Values { get; } = new List<Buffer>();

	public void GetBytes(Buffer buffer)
	{
		Assert.True(valueIndex < Values.Count);
		Assert.Equal(Values[valueIndex].Count, buffer.Count);

		Values[valueIndex].CopyTo(buffer);

		valueIndex++;
	}
}
