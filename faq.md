# Discover

Last updated: 12/23/2022

## What is tail2 continuous profiler?

tail2 is a *self-service continuous profiler* that can be run in your production environment.

## What is continuous profiling?

Continuous profiling is **always-on system-wide profiling**, rather than being limited to a specific application or process.

A continuous profiler is constantly running in the background, collecting data on the performance of the entire system. This allows developers to get a comprehensive view of the performance of their systems and applications.

## Why continuous profiling?

Continuous profiling is particularly useful for identifying issues that may not be immediately apparent when profiling a single application or process. For example, it can help developers quickly identify performance bottlenecks that are caused by interactions between multiple applications or processes, or by external factors such as kernel resource contention or networking hardware limitations.

It's **magical** to see exactly what your application is doing.

## What languages/runtimes are supported?

Currently we support native languages such as C/C++, Rust, Go and others.

Scripting languages support: Python3.11.

We don't currently support JIT runtimes but we are working on Java, .NET, Node.JS and wasmtime support.

## How to use tail2?

tail2 is designed to be easy to integrate, without *any* changes to your code.

Simply deploy the agent and view traces on the portal.

## How to download and use tail2?

It's really early in development. So please join our discord: [link](https://discord.gg/krReQzBB8T) to get the binary.
