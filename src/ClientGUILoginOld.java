/**
 * Created by XYJK on 1/15/2017.
 */
import javax.swing.*;
import java.awt.event.*;

public class ClientGUILoginOld extends JFrame {

    public static void main(String[] args) {
        ClientGUILoginOld frameTabel = new ClientGUILoginOld();
    }

    JButton blogin = new JButton("Login");
    JPanel panel = new JPanel();
    JTextField txuser = new JTextField(15);
    JPasswordField pass = new JPasswordField(15);

    ClientGUILoginOld(){
        super("Login Autentification");
        setSize(300,200);
        setLocation(500,280);
        panel.setLayout (null);


        txuser.setBounds(70,30,150,20);
        pass.setBounds(70,65,150,20);
        blogin.setBounds(110,100,80,20);

        panel.add(blogin);
        panel.add(txuser);
        panel.add(pass);

        getContentPane().add(panel);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
        actionlogin();
    }

    public void actionlogin(){
        blogin.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                String puname = txuser.getText();
                String ppaswd = pass.getText();
                if(puname.equals("test") && ppaswd.equals("12345")) {
                    ClientGUIMain regFace =new ClientGUIMain("localhost",1500);
                    regFace.setVisible(true);
                    dispose();
                } else {

                    JOptionPane.showMessageDialog(null,"Wrong Password / Username");
                    txuser.setText("");
                    pass.setText("");
                    txuser.requestFocus();
                }

            }
        });
    }
}