#include <stdio.h>
#include <stdlib.h>
#include <idp.hpp>
#include <loader.hpp>
#include <gdl.hpp>

// dump_cfgs dumps the control flow graph of each function contained within the
// executable and stores them as DOT files within a /tmp/punkt.XXXXXX directory.
void dump_cfgs() {
	char pattern[] = "/tmp/punkt.XXXXXX";
	char *dir = mkdtemp(pattern);
	if (dir == NULL) {
		warning("unable to create output directory `%s`", dir);
		return;
	}
	int nfuncs = get_func_qty();
	for (int i = 0; i < nfuncs; i++) {
		func_t *f = getn_func(i);
		ea_t faddr = f->start_ea;
		char title[32];
		qsnprintf(title, sizeof(title), "%08X", faddr);
		char dst_path[1024];
		qsnprintf(dst_path, sizeof(dst_path), "%s/%08X.dot", dir, faddr);
		if (!gen_flow_graph(dst_path, title, f, 0, 0, CHART_GEN_DOT)) {
			warning("unable to generate CFG for function at address %08X", faddr);
			continue;
		}
	}
	warning("punkt completed successfully :) DOT files stored in `%s`", dir);
}

int idaapi init(void) {
	return PLUGIN_OK;
}

bool idaapi run(size_t) {
	dump_cfgs();
	return true;
}

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL,           // plugin flags
	init,                 // initialize
	NULL,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	NULL,                 // long comment about the plugin
	NULL,                 // multiline help about the plugin
	"punkt",              // the preferred short name of the plugin
	"Ctrl-Shift-p"        // the preferred hotkey to run the plugin
};
