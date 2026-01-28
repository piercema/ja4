# @TEST-EXEC: zeek -NN JA4::JA4 |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
