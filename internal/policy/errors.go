package policy

import "errors"

// ErrTermsInvalid marks a per-object override sidecar that will not compile.
//
// It is separated from ErrNoPolicy because only this one is a property of the
// upload. The sidecar arrived with the object and is malformed in the bucket, so it
// is malformed on every retry no matter what the operator changes; the object has to
// be uploaded again. That makes it safe -- and correct -- for the worker to set the
// input aside rather than keep attempting it.
var ErrTermsInvalid = errors.New("per-object terms cannot be compiled")

// ErrNoPolicy marks a resolution that failed on the registry rather than on the
// object: no default policy is set, or an override named one that is not loaded.
//
// Deliberately NOT treated as permanent, even though it repeats. Two things make it
// different from ErrTermsInvalid. It is a deployment-wide fault, so every object in
// the bucket fails it at once -- and setting them all aside would empty the input
// bucket into processed/ unscrubbed, which is far worse than a queue that is merely
// stuck. And it heals on its own: watchPolicies hot-reloads the policy directory
// when the mounted ConfigMap changes, so a corrected policy is picked up without a
// restart, and the objects waiting on a backoff are then scrubbed normally.
//
// So these back off and keep waiting. The backoff alone is enough to fix the queue
// trap this class used to cause, because a non-zero attempt count is what stops
// orderKey sorting the object to the head of the bucket.
var ErrNoPolicy = errors.New("no policy could be resolved for this object")
