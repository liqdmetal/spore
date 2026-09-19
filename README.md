# cfl-corpus — ClusterFuzzLite storage branch

Corpus persistence for the ClusterFuzzLite fuzzing workflows
(.github/workflows/cflite_*.yml). Structure per the CFL docs:

    /corpus/<fuzz_target>/   — corpus files, one directory per fuzzer

Written by the batch and prune runs. Do not edit by hand. An earlier
run committed a source snapshot to the branch root by accident (empty
storage bootstrap); cleaned forward here — history retains it.
