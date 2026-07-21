/**
 * Joint Phase 19B limit: two images at this ceiling expand to about 26.7 MiB
 * when Base64 encoded, leaving bounded room inside the 32 MiB canonical
 * provider request body for prompts and JSON structure.
 */
export const MAX_PREPROCESSED_MEDIA_PART_BYTES = 10 * 1024 * 1024;

export const MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES = 32 * 1024 * 1024;
