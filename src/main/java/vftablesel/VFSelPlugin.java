import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "vftable reconstruction.",
	description = "Virtual table selection & reconstruction."
)
public class VFSelPlugin extends Plugin {

	public VFSelPlugin(PluginTool tool) {
		super(tool);

		tool.addAction(new VFTableSelectionAction(this, tool));
	}

	@Override
	public void init() {
		super.init();
	}
}
