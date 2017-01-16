import javax.sound.midi.Soundbank;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by XYJK on 1/15/2017.
 */
public class ClientGUILogin {
    private static JFrame frame;
    private JPanel panel1;
    private JTextField usernameField1;
    private JPasswordField passwordField1;
    private JTextField portField1;
    private JTextField hostField1;
    private JButton registerButton;
    private JButton loginButton;
    private FileReader fr;
    private BufferedReader br;

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
                if (usernameField1.getText().isEmpty() || passwordField1.getText().isEmpty() ||
                        portField1.getText().isEmpty() || hostField1.getText().isEmpty()){
                    JOptionPane.showMessageDialog(frame, "Field(s) is/are empty", "INFORMATION" , JOptionPane.INFORMATION_MESSAGE);
                }


               else if (checkUser() == true) {
                    ClientGUIMain mainGUI = new ClientGUIMain(hostField1.getText(), Integer.parseInt(portField1.getText()));
                    mainGUI.setVisible(true);
                    frame.dispose();
                }

            }
        });
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
    }

    public boolean checkUser() {
        String currentLine;
        try {
            fr = new FileReader("Credentials");
            br = new BufferedReader(fr);
            while ((currentLine = br.readLine()) != null) {
                if (currentLine.matches("[a-zA-Z0-9]+:.*")) {
                    Pattern pattern = Pattern.compile("([a-zA-Z0-9]+):(.*)");
                    Matcher m = pattern.matcher(currentLine);
                    if (m.find()) {
                        if (m.group(1).equals(usernameField1.getText()) && m.group(2).equals(passwordField1.getText())) {
                            System.out.println("Found value: " + m.group(2));
                            return true;
                        }
                    }
                }
            }
            br.close();
            fr.close();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        JOptionPane.showMessageDialog(frame, "Username/Password Not Found", "Error" , JOptionPane.WARNING_MESSAGE);
        return false;
    }
}