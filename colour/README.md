# colour

Colour assigns a colour to the selected function.

## Hotkey

To add a hotkey for the colour plugin, modify `ida/idc/ida.idc` as follows:

```diff
diff --git a/ida.idc b/ida.idc
index 33fcd6d..2fca072 100644
--- a/ida.idc
+++ b/ida.idc
@@ -88,4 +88,11 @@ static main(void)
 
   // uncomment this line to remove full paths in the debugger process options:
   // set_inf_attr(INF_LFLAGS, LFLG_DBG_NOPATH|get_inf_attr(INF_LFLAGS));
+
+  AddHotkey("c", "py_colour");
+}
+
+static py_colour()
+{
+  RunPythonStatement("execfile('/path/to/colour.py')");
 }
```
