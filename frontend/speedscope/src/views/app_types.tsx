export interface ICallTree<T> {
    item: T,
    total_samples: number,
    self_samples: number,
    children: ICallTree<T>[] | null,
}

export enum CodeType {
    Native = "Native",
    Python = "Python",
    Kernel = "Kernel",
}

export interface IResolvedFrame {
    name: string,
    code_type: CodeType,
}

export type CallTree = ICallTree<IResolvedFrame | null>
