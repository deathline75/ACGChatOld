import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by XYJK on 1/15/2017.
 */
public class ClientGUILogin {
    private static JFrame frame;
    private JPanel panel1;
    private JTextField textField1;
    private JPasswordField passwordField1;
    private JTextField textField2;
    private JTextField textField3;
    private JButton registerButton;
    private JButton loginButton;

    public static void main(String[] args) {
        frame = new JFrame("ClientGUILogin");
        frame.setContentPane(new ClientGUILogin().panel1);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    public ClientGUILogin() {
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ClientGUIMain adsf = new ClientGUIMain("localhost",1500);
                adsf.setVisible(true);
                frame.dispose();
            }
        });
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
    }
}
