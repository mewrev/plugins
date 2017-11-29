# The call_range script produces a call graph for a specified address range,
# with 1-level of incoming and outgoing edges to and from the address range.

import idaapi
import idautils
import tempfile

# ref: https://github.com/darx0r/Reef/blob/master/src/Reef.py
XREF_TYPE2STR = {idaapi.fl_U : "User Defined",
                 idaapi.fl_CF: "Far Call",
                 idaapi.fl_CN: "Near Call",
                 idaapi.fl_JF: "Far Jump",
                 idaapi.fl_JN: "Near Jump"}

ALL_XREFS = 0

# find_callees returns the callees of the given function (i.e. the outgoing
# cross-references).
def find_callees(func_ea):
	callers = []
	items = idautils.FuncItems(func_ea)
	for item in items:
		for ref in idautils.XrefsFrom(item, ALL_XREFS):
			if ref.type not in XREF_TYPE2STR:
				continue
			if ref.to in items:
				continue
			callers.append(ref.to)
	return callers

# find_callers returns the callers of the given function (i.e. the incoming
# cross-references).
def find_callers(func_ea):
	callees = []
	items = idautils.FuncItems(func_ea)
	for item in items:
		for ref in idautils.XrefsTo(item, ALL_XREFS):
			if ref.type not in XREF_TYPE2STR:
				continue
			if ref.frm in items:
				continue
			callees.append(ref.frm)
	return callees

# name_from_ea returns the name associated with the given address.
def name_from_ea(ea):
	name = GetFunctionName(ea)
	if name:
		return name
	name = get_name(ea)
	if name:
		return name
	print("unable to locate name for 0x%08X" % ea)
	exit(1)

# gen_dot_graph produces a call graph for a specified address range (first and
# last function address of the address range, inclusive), with 1-level of
# incoming and outgoing edges to and from the address range.
def gen_dot_graph(first_ea, last_ea):
	# in_range reports whether the given address is within the specified address
	# range.
	def in_range(ea):
		return first_ea <= ea and ea <= last_ea
	# Nodes inside the address range.
	in_nodes = {}
	# Nodes outside the address range.
	out_nodes = {}
	edges = []
	ea = BeginEA()
	for from_ea in Functions(SegStart(ea), SegEnd(ea)):
		from_name = GetFunctionName(from_ea)
		callees = find_callees(from_ea)
		for to_ea in callees:
			if not in_range(from_ea) and not in_range(to_ea):
				# Skip edge if neither the from nor the to node is within the
				# address range.
				continue
			to_name = name_from_ea(to_ea)
			if in_range(from_ea):
				in_nodes[from_name] = True
			else:
				out_nodes[from_name] = True
			if in_range(to_ea):
				in_nodes[to_name] = True
			else:
				out_nodes[to_name] = True
			edge = (from_name, to_name)
			edges.append(edge)
	#with tempfile.NamedTemporaryFile(prefix="callgraph_", suffix=".dot") as f:
	with open('/tmp/call_range_%06X-%06X.dot' % (first_ea, last_ea), 'w') as f:
		f.write('digraph {\n')
		for i in in_nodes:
			f.write('\t"%s" [fillcolor=lightblue style=filled]\n' % i)
		for o in out_nodes:
			f.write('\t"%s" [fillcolor=red style=filled]\n' % o)
		for edge in edges:
			(from_name, to_name) = edge
			f.write('\t"%s" -> "%s"\n' % (from_name, to_name))
		f.write("}")
		print('Call graph stored at "%s"' % f.name)

first = AskAddr(0, "First function address in range.")
last = AskAddr(0, "Last function address in range.")
gen_dot_graph(first, last)
