import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class WEcRSAED {

	private static String ALGORITHM = "RSA";
	private int[] RSA_KEY_SIZE = new int[] {512, 1024, 1536, 2048, 2560, 3072, 3584, 4096};
	
	private static int KEY_SIZE;
	private static int CIPHER_BLOCK_SIZE;
	private static int DE_CIPHER_BLOCK_SIZE;
	private static String PUBLIC_KEY_FILE_NAME;
	private static String PRIVATE_KEY_FILE_NAME;
	
	
	private JFrame frmRsaPerformanceTest;
	private JTextField txtFilesize;
	private JComboBox cbxRsa;
	private JTextField txtTimes;
	private JTextField txtElapse;
	private JLabel lblStatus;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					WEcRSAED window = new WEcRSAED();
					window.frmRsaPerformanceTest.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public WEcRSAED() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmRsaPerformanceTest = new JFrame();
		frmRsaPerformanceTest.setTitle("RSA Performance Test");
		frmRsaPerformanceTest.setBounds(100, 100, 450, 300);
		frmRsaPerformanceTest.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JPanel panel = new JPanel();
		frmRsaPerformanceTest.getContentPane().add(panel,  BorderLayout.CENTER);
		panel.setLayout(null);
		
		JLabel lblFilesize = new JLabel("Filesize");
		lblFilesize.setBounds(22, 32, 46, 15);
		panel.add(lblFilesize);
		
		txtFilesize = new JTextField();
		txtFilesize.setBounds(114, 29, 213, 21);
		panel.add(txtFilesize);
		txtFilesize.setColumns(10);
		
		JLabel lblBytes = new JLabel("Bytes");
		lblBytes.setBounds(358, 32, 46, 15);
		panel.add(lblBytes);
		
		JLabel lblRsa = new JLabel("RSA:");
		lblRsa.setBounds(22, 78, 46, 15);
		panel.add(lblRsa);
		
		cbxRsa = new JComboBox();
		cbxRsa.setModel(new DefaultComboBoxModel(new String[] {"RSA_512", "RSA_1024", "RSA_1536", "RSA_2048", "RSA_2560", "RSA_3072", "RSA_3584", "RSA_4096"}));
		cbxRsa.setBounds(114, 75, 213, 21);
		panel.add(cbxRsa);
		
		JLabel lblTimes = new JLabel("Times");
		lblTimes.setBounds(22, 128, 46, 15);
		panel.add(lblTimes);
		
		txtTimes = new JTextField();
		txtTimes.setBounds(114, 125, 213, 21);
		panel.add(txtTimes);
		txtTimes.setColumns(10);
		
		JButton btnExecute = new JButton("Execute");
		btnExecute.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Thread execute = new Thread() {
					public void run() {
						try {
							lblStatus.setText("Running");
							int fileSize = Integer.parseInt(txtFilesize.getText());
							int times = Integer.parseInt(txtTimes.getText());
							
							byte[] original = new byte[fileSize];
							byte[] encrypt;
							byte[] decrypt;
							SecureRandom sr = new SecureRandom();
							sr.nextBytes(original);
							
							KEY_SIZE = RSA_KEY_SIZE[cbxRsa.getSelectedIndex()];
							CIPHER_BLOCK_SIZE = (KEY_SIZE) / 512 * 50;
							DE_CIPHER_BLOCK_SIZE = (KEY_SIZE) / 512  * 64;
							PUBLIC_KEY_FILE_NAME = "public_" + KEY_SIZE + ".key";
							PRIVATE_KEY_FILE_NAME = "private_" + KEY_SIZE + ".key";
							
							if (!areKeysPresent()) {
								generateKey();
							}
							
							File PUBLIC_KEY_FILE = new File(PUBLIC_KEY_FILE_NAME);
							File PRIVATE_KEY_FILE = new File(PRIVATE_KEY_FILE_NAME);
							
							final PublicKey publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(readFile(PUBLIC_KEY_FILE)));
							final PrivateKey privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(readFile(PRIVATE_KEY_FILE)));
							
							long msbefore = 0;
							long msafter = 0;
							long enc_total = 0;
							long dec_total = 0;
							
							for (int i = 0; i < times; i++) {
								msbefore = getCurrentTime();
								encrypt = encrypt(original, publicKey);
								msafter = getCurrentTime();
								enc_total = enc_total + (msafter - msbefore);
								
								msbefore = getCurrentTime();
								decrypt = decrypt(encrypt, privateKey);
								msafter = getCurrentTime();
								dec_total = dec_total + (msafter - msbefore);
							}
							
							String result = "AVENC: " + (float)enc_total/times + " ms / AVDEC: " + (float)dec_total/times + " ms";
							txtElapse.setText(result);
							
							
							lblStatus.setText("Ready");
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				};
				execute.start();
			}
		});
		btnExecute.setBounds(337, 228, 87, 23);
		panel.add(btnExecute);
		
		JLabel lblElapse = new JLabel("Elapse");
		lblElapse.setBounds(22, 176, 46, 15);
		panel.add(lblElapse);
		
		txtElapse = new JTextField();
		txtElapse.setBounds(114, 173, 213, 21);
		panel.add(txtElapse);
		txtElapse.setColumns(10);
		
		lblStatus = new JLabel("Ready");
		lblStatus.setBounds(22, 232, 46, 15);
		panel.add(lblStatus);
	}

	public JTextField getTxtFilesize() {
		return txtFilesize;
	}
	public JComboBox getCbxRsa() {
		return cbxRsa;
	}
	public JTextField getTxtTimes() {
		return txtTimes;
	}
	public JTextField getTxtElapse() {
		return txtElapse;
	}
	public JLabel getLblStatus() {
		return lblStatus;
	}
	
	public static long getCurrentTime() {
		Date today;
		today = new Date();
		return today.getTime();
	}
	
	public static void generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(KEY_SIZE);
			final KeyPair keyPair = keyGen.generateKeyPair();
			
			byte[] publicKey = keyPair.getPublic().getEncoded();
			byte[] privateKey = keyPair.getPrivate().getEncoded();
			
			writeFile(publicKey, PUBLIC_KEY_FILE_NAME);
			writeFile(privateKey, PRIVATE_KEY_FILE_NAME);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static boolean areKeysPresent() {
		File privateKey = new File(PRIVATE_KEY_FILE_NAME);
		File publicKey = new File(PUBLIC_KEY_FILE_NAME);
		
		if (privateKey.exists() && publicKey.exists()) {
			return true;
		} else {
			return false;
		}
	}
	
	public static byte[] encrypt(byte[] data, PublicKey key) throws Exception {
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] result = null;
		
		ByteArrayInputStream bis = new ByteArrayInputStream(data);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		int read;
		byte[] buffer = new byte[CIPHER_BLOCK_SIZE];
		while((read = bis.read(buffer)) != -1)  {
			byte[] bufferCipher = cipher.doFinal(buffer);
			if (result == null) {
				result = bos.toByteArray();
			} else {
				byte[] newresult = new byte[result.length + bufferCipher.length];
				System.arraycopy(result, 0, newresult, 0, result.length);
				System.arraycopy(bufferCipher, 0, newresult, result.length, bufferCipher.length);
				result = newresult;
			}
		}
		return result;
	}
	
	public static byte[] decrypt(byte[] data, PrivateKey key) throws Exception{
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] result = null;
		
		ByteArrayInputStream bis = new ByteArrayInputStream(data);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		int read;
		byte[] buffer = new byte[DE_CIPHER_BLOCK_SIZE];
		while((read = bis.read(buffer)) != -1)  {
			byte[] bufferCipher = cipher.doFinal(buffer);
			if (result == null) {
				result = bos.toByteArray();
			} else {
				byte[] newresult = new byte[result.length + bufferCipher.length];
				System.arraycopy(result, 0, newresult, 0, result.length);
				System.arraycopy(bufferCipher, 0, newresult, result.length, bufferCipher.length);
				result = newresult;
			}
		}
		return result;
	}
	
	public static byte[] readFile(File file) throws IOException {
		byte[] data;
		
		data = new byte[(int)file.length()];
		FileInputStream fis = new FileInputStream(file);
		fis.read(data);
		fis.close();
		return data;
	}
	
	public static void writeFile(byte[] data, String fileName) throws IOException {
		FileOutputStream fos = new FileOutputStream(fileName);
		fos.write(data);
		fos.close();
	}
}
