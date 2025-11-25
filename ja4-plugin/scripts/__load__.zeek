module FINGERPRINT;

export { type Info: record {}; }
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./utils/common
@load ./utils/ssl-consts
@load ./helpers
@load ./main