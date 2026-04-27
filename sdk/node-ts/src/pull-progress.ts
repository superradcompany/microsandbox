/** Image-pull progress event emitted during `createWithPullProgress()`. */
export type PullProgress =
  | { kind: "resolving"; reference: string }
  | {
      kind: "resolved";
      reference: string;
      manifestDigest: string;
      layerCount: number;
      totalDownloadBytes: number | null;
    }
  | {
      kind: "layerDownloadProgress";
      layerIndex: number;
      digest: string;
      downloadedBytes: number;
      totalBytes: number | null;
    }
  | {
      kind: "layerDownloadComplete";
      layerIndex: number;
      digest: string;
      downloadedBytes: number;
    }
  | { kind: "layerDownloadVerifying"; layerIndex: number; digest: string }
  | { kind: "layerMaterializeStarted"; layerIndex: number; diffId: string }
  | {
      kind: "layerMaterializeProgress";
      layerIndex: number;
      bytesRead: number;
      totalBytes: number;
    }
  | { kind: "layerMaterializeWriting"; layerIndex: number }
  | { kind: "layerMaterializeComplete"; layerIndex: number; diffId: string }
  | { kind: "stitchMergingTrees"; layerCount: number }
  | { kind: "stitchWritingFsmeta" }
  | { kind: "stitchWritingVmdk" }
  | { kind: "stitchComplete" }
  | { kind: "complete"; reference: string; layerCount: number };
