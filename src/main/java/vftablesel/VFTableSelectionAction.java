import java.util.LinkedList;
import java.util.List;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;


public class VFTableSelectionAction extends ListingContextAction {
	private PluginTool tool;

    public VFTableSelectionAction(VFSelPlugin plugin, PluginTool tool) {
		super("vftable creation from selection", plugin.getName());
		this.tool = tool;
		this.setPopupMenuData(new MenuData(new String[] { "Data", "Create Vftable..." }, null, "BasicData"));
	}

	private String getSymbolFullName(Symbol s) {
		if(s == null) return null;
		return NamespaceUtils.getNamespaceQualifiedName(s.getParentNamespace(), s.getName(), true);
	}

	public List<Function> getVtableFunctions(FlatProgramAPI api, Address start, Address end) {
		Address cur = start;
		List<Function> res = new LinkedList<Function>();
		AddressFactory factory = api.getAddressFactory();

		while(cur.compareTo(end) <= 0) {
			try {
				Address funcAddr = factory.getAddress(factory.getDefaultAddressSpace().getSpaceID(), api.getLong(cur));
				Function f = api.getFunctionAt(funcAddr);
				res.add(f);
			} catch(MemoryAccessException e) {
				res.add(null);
			}
			cur = cur.add(cur.getPointerSize());
		}

		return res;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Program program = context.getProgram();
		if(program == null) return;

		FlatProgramAPI programAPI = new FlatProgramAPI(program);

		ProgramSelection sel = context.getSelection();
		if(sel == null) return;

		Address start = sel.getMinAddress();
		Address end = sel.getMaxAddress();
		int ptr_size = start.getPointerSize();
		Address tinfo_addr = start.subtract(2 * ptr_size);
		
		VFTableSelectionDialog dialog = new VFTableSelectionDialog(this.tool, getSymbolFullName(programAPI.getSymbolAt(tinfo_addr)));
		String vfname = dialog.showSelection();
		if(vfname == null) return;

		List<Function> vfcts = this.getVtableFunctions(programAPI, start, end);
		if(vfcts.size() == 0) return;

		ProgramBasedDataTypeManager dtMgr = program.getDataTypeManager();
		int tid = dtMgr.startTransaction("vftable definition");

		Category vtableCat  = dtMgr.createCategory(new CategoryPath("/vftables"));
		Category vfctCat  = dtMgr.createCategory(new CategoryPath("/vfunctions"));

		StructureDataType vtableStruct = new StructureDataType(vtableCat.getCategoryPath(), vfname, 0);
		for(Function f : vfcts) {
			PointerDataType pfdd;
			FunctionDefinitionDataType fdd;
			String fname = null, fcomm = null;

			if(f == null) {
				pfdd = new PointerDataType(dtMgr);
			} else {
				String funcName = f.getParentNamespace() != null ? f.getParentNamespace().getName() + "::" + f.getName() : f.getName();

				Msg.info(this, "Creating function definition: " + funcName);

				fdd = new FunctionDefinitionDataType(vfctCat.getCategoryPath(), funcName, f.getSignature());
				pfdd = new PointerDataType(fdd);
				try {
					dtMgr.addDataType(fdd, DataTypeConflictHandler.REPLACE_HANDLER);
	
					pfdd.setCategoryPath(vfctCat.getCategoryPath());
					dtMgr.addDataType(pfdd, DataTypeConflictHandler.REPLACE_HANDLER);
				} catch (DuplicateNameException e) {
					// do nothing
				}

				fname = fdd.getName();
				fcomm = f.getEntryPoint().toString();
			}

			vtableStruct.add(pfdd, ptr_size, fname, fcomm);
		}

		Msg.info(this, "Creating vtable: " + vtableStruct.getName());

		dtMgr.addDataType(vtableStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		dtMgr.endTransaction(tid, true);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		ProgramSelection sel = context.getSelection();
		if (sel == null || sel.isEmpty()) return false;
		return true;
	}
};