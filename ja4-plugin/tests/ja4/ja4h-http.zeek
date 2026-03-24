# @TEST-EXEC: zeek -C -r $TRACES/http1-with-cookies.pcapng ${ZEEK_PLUGIN_PATH}/scripts/ja4h %INPUT
# @TEST-EXEC: zeek-cut ja4h < http.log | sort > output
# @TEST-EXEC: btest-diff output
