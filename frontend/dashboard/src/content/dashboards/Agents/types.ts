export type ProbeTypes = "Perf" | "Uprobe";

interface IProbeState {
  is_running: boolean;
}

interface IProbeInfo {
  0: IProbe;
  1: IProbeState;
}

export interface IAgentProps {
  host_name: string;
  agent: IAgent;
}

export interface IAgent {
  is_halted: boolean,
  probes: IProbeInfo[];
}

export interface IAgents {
  [id: string]: IAgent;
}

export interface INewProbeModalProps {
  name: string;
  open: boolean;
  handleClose: () => void;
}

export type IScope = {
  type: "Pid";
  pid: number;
} | {
  type: "SystemWide";
};

export type IPerfProbe = {
  type: "Perf";
  scope: IScope;
  period: number;
}

export type IUprobeProbe = {
  type: "Uprobe";
  scope: IScope;
  uprobe: string;
}

export type ICallTreeParams = {
  probe: IProbe;
  host_name: string;
}

export type IProbe = IPerfProbe | IUprobeProbe;

export function make_perf_probe(scope: IScope, period: number): IPerfProbe {
    return {
        type: "Perf",
        scope,
        period,
    };
}

export function make_uprobe_probe(scope: IScope, uprobe: string): IUprobeProbe {
    return {
        type: "Uprobe",
        scope,
        uprobe,
    };
}

export async function stop_probe(name: string, probe:IProbe) {
    let args = {
        name: name,
        probe: JSON.stringify(probe),
    };
    await fetch("/api/agent/stop_probe?" + new URLSearchParams(args));
};

export async function start_probe(name: string, probe:IProbe) {
    let args = {
        name: name,
        probe: JSON.stringify(probe),
    };
    await fetch("/api/agent/start_probe?" + new URLSearchParams(args));
};
