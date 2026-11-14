declare module "snarkjs" {
  export const groth16: {
    verify(
      vk: Record<string, unknown>,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
    fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
  };
}
