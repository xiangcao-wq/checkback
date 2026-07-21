import { z } from "zod";

export const AnalysisModeSchema = z.enum([
  "restoration",
  "inventory",
  "condition",
  "completeness",
]);

export type AnalysisMode = z.infer<typeof AnalysisModeSchema>;

export const DEFAULT_ANALYSIS_MODE: AnalysisMode = "restoration";
