import java.awt.Dimension;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.w3c.dom.events.MouseEvent;

import docking.ReusableDialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

public class VFTableSelectionDialog extends ReusableDialogComponentProvider {
    private PluginTool tool;
    private JTextField vftableTextField;
    private String selection;
    
    public VFTableSelectionDialog(PluginTool tool, String vfname) {
        super("Create virtual table", true, true, true, false);
        this.tool = tool;
        this.selection = null;

        this.addWorkPanel(this.buildMainPanel(vfname));
        this.addOKButton();
		this.addCancelButton();
        this.setOkButtonText("Create");
        this.setDefaultButton(this.okButton);

        this.rootPanel.setPreferredSize(new Dimension(600, 64));
    }

    public String showSelection() {
        tool.showDialog(this);
        return this.selection;
    }

    private JPanel buildMainPanel(String vfname) {
        JPanel namePanel = new JPanel();
        namePanel.setLayout(new BoxLayout(namePanel, BoxLayout.Y_AXIS));
		TitledBorder nameBorder = BorderFactory.createTitledBorder("Vftable name");
		namePanel.setBorder(nameBorder);
        this.vftableTextField = new JTextField() {
            // make sure our height doesn't stretch
			@Override
			public Dimension getMaximumSize() {
				Dimension d = super.getMaximumSize();
				d.height = getPreferredSize().height;
				return d;
			}
		};
        if(vfname != null) this.vftableTextField.setText(vfname);
		namePanel.add(this.vftableTextField);

        return namePanel;
    }

    @Override
	protected void okCallback() {
        String val = this.vftableTextField.getText();
        if(val == null || val.length() == 0) {
            Msg.showError(this, null, "Invalid name", "Please provide a vftable name");
        } else {
            this.selection = val;
            this.close();
        }
    }

}
