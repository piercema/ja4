
#include "Plugin.h"
#include <string>
#include <cctype>
#include <sstream>
#include <vector>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/Conn.h"
#include "ja4.h"

namespace plugin { namespace JA4_JA4 { Plugin plugin; } }

using namespace plugin::JA4_JA4;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "JA4::JA4";
	config.description = "Calculate the JA4 hash for an encrypted connection";
	config.version.major = 0;

	config.version.minor = 1;
	config.version.patch = 0;

	return config;
	}