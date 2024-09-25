# Dev Tunnels Library Development
This document contains information about building, debugging, testing,
and benchmarking the C# and TS SSH libraries.

## Prerequisites
 - Install the **.NET SDK** matching the version specified in
 [`global.json`](./global.json).
 - Install **Node.js** version 10.x or above.
 - Install the [Azure Artifacts Credential Provider](https://github.com/Microsoft/artifacts-credprovider)
 - Install dependency packages, and the `gulp` CLI:
   ```
   dotnet restore --interactive
   npm install
   ```

## Building
Command-line builds are driven by scripts in `build.js`.

| Command            | Description                     |
| ------------------ | ------------------------------- |
| `npm run build`    | Build everything.               |
| `npm run build-cs` | Build C# code and tests.        |
| `npm run build-ts` | Build TS code and tests.        |
| `npm run pack`     | Produce NuGet and npm packages. |

Append `--release` to a build or pack command to specify release flavor
instead of the default debug.

The .NET builds produce 2 outputs for each assembly, due to
multi-targeting to .NET Standard 2.0 and 2.1.

## Testing
### .NET Testing
```
npm run test-cs
```
To run/debug an individual test case or subset of test cases matching a
substring, use a command similar to the following:
```
npm run test-cs --framework net8.0 --filter crypto
```
Or open `SSH.sln` in Visual Studio 2019 and use the Test Explorer.

A few of the .NET test cases test interop against the TypeScript lib,
so that code must have been built also.

### Node.js Testing
```
npm run test-ts
```
To run/debug an individual test case or subset of test cases matching a
substring, use a command similar to the following:
```
npm run test-ts --filter crypto
```
Or open the repo root in VS Code and use the **Mocha Test Explorer** extension
(recommended by the repo settings).

### Browser Testing
 1. Build the TS code, and prepare the browser bundle:
   ```
   npm run build-ts
   npm run build-browsertest
   ```
 2. Start the test server that supports the node<->browser interop test cases.
 (This is optional; if the server is not running then those few test cases will fail
 and you can ignore them.)
   ```
   npm run test-server
   ```
 3. Then open `test/ts/ssh-test/test.html` in a browser, and it runs all the
 test cases.

To run an individual test case in the browser, click the small (>) icon next to
a test case to go to a page for just that test, afterward you can refresh the page
to reload code and re-run the test.

Use the browser F12 tools to debug. Also, tracing messages from tests go to the
browser console.

### Code Coverage

Online builds produce a detailed code coverage report of C# code. Just click on the
**Code Coverage** tab at the top of the completed build page of any PR or CI build.

(Code coverage is not implemented for the TypeScript library.)

## Tracing
SSH protocol messages and other noteworthy events are emitted to a tracing
system, depending on the platform:
  - In .NET, pass a `TraceSource` instance to the `SshSclientSession` or
    `SshServerSession` constructor, and [configure the TraceSource listeners
    and filters, for example:
    ```C#
    traceSource.Listeners.Add(new ConsoleTraceListener());
    traceSource.Switch.Level = SourceLevels.All;
    ```

  - In TypeScript, assign a function to the `SshSession.trace` property, for example:
    ```TypeScript
    session.trace = (level, eventId, msg) => {
      if (level === 'error') console.error(msg);
      else if (level === 'warning') console.warn(msg);
      else console.log(msg);
    }
    ```

Channel data tracing is not enabled by default. To enable it
(_WARNING: very verbose_) set `SshSessionConfiguration.TraceChannelData = true`

## Benchmarking
There are some benchmarks that measure performance characteristics of both
C# and TS libs.
 1. Build debug or release flavor first. C# debug benchmarks capture statistics
 about memory allocations and copies; release benchmarks are of course faster.
 (Node is the same either way.)
 2. Run `npm run bench-cs` or `npm run bench-ts`. (Unlike others, these tasks use
 release flavor by default. Add `--debug` to use debug flavor instead.)

It is also possible to run a single benchmark scenario, for example:
```
npm run bench-cs --scenario encrypted-200
```
