package edu.uiuc.ncsa.oa4mp;

import javax.swing.*;

/**
 * Insert the type's description here.
 * Creation date: (12/20/2019 %r)
 */
public class MyApp {
	private JFrame ivjJFrame1 = null;
	private JPanel ivjJFrameContentPane = null;
	private JPanel ivjGeneral = null;
	private JTabbedPane ivjGeneralBean = null;
	private JLabel ivjJLabel1 = null;
	private JLabel ivjJLabel2 = null;
	private JLabel ivjJLabel3 = null;
	private JTabbedPane ivjJTabbedPane2 = null;
	private JTabbedPane ivjJTabbedPane3 = null;
/**
 * Return the JTabbedPane1 property value.
 * @return  JTabbedPane
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private JTabbedPane getGeneralBean() {
	if (ivjGeneralBean == null) {
		try {
			ivjGeneralBean = new  JTabbedPane();
			ivjGeneralBean.setName("GeneralBean");
			ivjGeneralBean.setBounds(13, 8, 1039, 487);
			ivjGeneralBean.insertTab("General", null, getGeneral(), null, 0);
			ivjGeneralBean.insertTab("Comments", null, getJTabbedPane2(), null, 1);
			ivjGeneralBean.insertTab("Runtime", null, getJTabbedPane3(), null, 2);
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjGeneralBean;
}
/**
 * Return the Page property value.
 * @return  JPanel
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JPanel getGeneral() {
	if (ivjGeneral == null) {
		try {
			ivjGeneral = new  JPanel();
			ivjGeneral.setName("General");
			ivjGeneral.setLayout(null);
			getGeneral().add(getJLabel1(), getJLabel1().getName());
			getGeneral().add(getJLabel2(), getJLabel2().getName());
			getGeneral().add(getJLabel3(), getJLabel3().getName());
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjGeneral;
}
/**
 * Return the JFrame1 property value.
 * @return  JFrame
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JFrame getJFrame1() {
	if (ivjJFrame1 == null) {
		try {
			ivjJFrame1 = new  JFrame();
			ivjJFrame1.setName("JFrame1");
			ivjJFrame1.setDefaultCloseOperation( WindowConstants.DISPOSE_ON_CLOSE);
			ivjJFrame1.setBounds(86, 54, 1061, 525);
			getJFrame1().setContentPane(getJFrameContentPane());
			// user code begin {1}
			ivjJFrame1.setVisible(true);
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJFrame1;
}
/**
 * Return the JFrameContentPane property value.
 * @return  JPanel
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JPanel getJFrameContentPane() {
	if (ivjJFrameContentPane == null) {
		try {
			ivjJFrameContentPane = new  JPanel();
			ivjJFrameContentPane.setName("JFrameContentPane");
			ivjJFrameContentPane.setLayout(null);
			getJFrameContentPane().add(getGeneralBean(), getGeneralBean().getName());
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJFrameContentPane;
}
/**
 * Return the JLabel1 property value.
 * @return  JLabel
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JLabel getJLabel1() {
	if (ivjJLabel1 == null) {
		try {
			ivjJLabel1 = new  JLabel();
			ivjJLabel1.setName("JLabel1");
			ivjJLabel1.setText("JLabel1");
			ivjJLabel1.setBounds(57, 49, 60, 20);
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJLabel1;
}
/**
 * Return the JLabel2 property value.
 * @return  JLabel
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JLabel getJLabel2() {
	if (ivjJLabel2 == null) {
		try {
			ivjJLabel2 = new  JLabel();
			ivjJLabel2.setName("JLabel2");
			ivjJLabel2.setText("JLabel2");
			ivjJLabel2.setBounds(57, 127, 60, 20);
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJLabel2;
}
/**
 * Return the JLabel3 property value.
 * @return  JLabel
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JLabel getJLabel3() {
	if (ivjJLabel3 == null) {
		try {
			ivjJLabel3 = new  JLabel();
			ivjJLabel3.setName("JLabel3");
			ivjJLabel3.setText("JLabel3");
			ivjJLabel3.setBounds(57, 215, 60, 20);
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJLabel3;
}
/**
 * Return the JTabbedPane2 property value.
 * @return  JTabbedPane
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JTabbedPane getJTabbedPane2() {
	if (ivjJTabbedPane2 == null) {
		try {
			ivjJTabbedPane2 = new  JTabbedPane();
			ivjJTabbedPane2.setName("JTabbedPane2");
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJTabbedPane2;
}
/**
 * Return the JTabbedPane3 property value.
 * @return  JTabbedPane
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private  JTabbedPane getJTabbedPane3() {
	if (ivjJTabbedPane3 == null) {
		try {
			ivjJTabbedPane3 = new  JTabbedPane();
			ivjJTabbedPane3.setName("JTabbedPane3");
			// user code begin {1}
			// user code end
		} catch (java.lang.Throwable ivjExc) {
			// user code begin {2}
			// user code end
			handleException(ivjExc);
		}
	}
	return ivjJTabbedPane3;
}
/**
 * Called whenever the part throws an exception.
 * @param exception java.lang.Throwable
 */
private void handleException(java.lang.Throwable exception) {

	/* Uncomment the following lines to print uncaught exceptions to stdout */
	// System.out.println("--------- UNCAUGHT EXCEPTION ---------");
	// exception.printStackTrace(System.out);
}
/**
 * Initialize the class.
 */
/* WARNING: THIS METHOD WILL BE REGENERATED. */
private void initialize() {
	try {
		// user code begin {1}
		// user code end
	} catch (java.lang.Throwable ivjExc) {
		handleException(ivjExc);
	}
	// user code begin {2}
	// user code end
}
/**
 * main entrypoint - starts the part when it is run as an application
 * @param args java.lang.String[]
 */
public static void main(java.lang.String[] args) {
	try {
		MyApp aMyApps;
		aMyApps = new MyApp();
aMyApps.getJFrame1().setVisible(true);
		
		System.out.println("yo!");
	} catch (Throwable exception) {
		System.err.println("Exception occurred in main() of java.lang.Object");
		exception.printStackTrace(System.out);
	}
}
/**
 * MyApps constructor comment.
 */
public MyApp() {
	super();
	initialize();
}
}