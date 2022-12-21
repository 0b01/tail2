# Discover

## What is tail2 ambient profiler?

tail2 is a *self-service ambient profiler* that can be run in your production environment.

## What is ambient profiling?

Ambient profiling is **system-wide continuous profiling**, rather than being limited to a specific application or process.

In ambient profiling, the profiler is constantly running in the background, collecting data on the performance of the entire system.  This allows developers to get a comprehensive view of the performance of their systems and applications.

## Why ambient profiling?

Ambient profiling is particularly useful for identifying issues that may not be immediately apparent when profiling a single application or process. For example, it can help developers quickly identify performance bottlenecks that are caused by interactions between multiple applications or processes, or by external factors such as kernel resource contention or networking hardware limitations.

At a previous job, we had a service that required us to be on call. Every day at 3am, we would get a notification that the cpu cores was maxing out and had to manually reboot the service. We couldn't figure out why it was happening, and it was causing a lot of frustration and disruption. One day, I decided to debug the issue and it turns out there was an infinite loop in the *database extension* we were using. With ambient profiling, we could have easily found the problem much sooner. It would allow us to identify the root cause by looking at the flamegraph for that time frame.

## How to use tail2?

tail2 is designed to be easy to integrate, without any change to your code.

Simply deploy the agent to your environment and go to the portal to configure the types of profiling you would like the agent to run.

## How does tail2 work?

tail2 does system-wide stack sampling with extended Berkeley Packet Filter(eBPF) in the Linux kernel. It registers BPF programs for kernel events, which would pause program execution and run a sophisticated BPF program to unwind user stacks.

We can attach to perf events as well as user functions. For example, we sample memory leak with malloc/free, unnecessary memory copying with memcpy and cache efficiency by attaching to cache misses etc..