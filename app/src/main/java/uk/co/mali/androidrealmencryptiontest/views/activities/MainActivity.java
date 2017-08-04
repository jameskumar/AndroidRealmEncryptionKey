package uk.co.mali.androidrealmencryptiontest.views.activities;

import android.content.DialogInterface;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import butterknife.BindView;
import butterknife.ButterKnife;
import uk.co.mali.androidrealmencryptiontest.R;
import uk.co.mali.androidrealmencryptiontest.views.adapter.KeyRecyclerAdapter;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String CIPHER_TYPE = "RSA/ECB/PKCS1PADDING";
    private static final String CIPHER_PROVIDER = "AndroidOpenSSL";

    @BindView(R.id.aliasText)
    EditText mAliasText;

    @BindView(R.id.startText)
    EditText mStartText;

    @BindView(R.id.decryptedText)
    EditText mDecryptText;

    @BindView(R.id.encryptedText)
    EditText mEncryptedText;

    @BindView(R.id.listView)
    ListView mListView;

    private KeyRecyclerAdapter listAdapter;

    KeyStore keyStore;

    List<String> mKeyAliases;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);

        try {
            keyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

        } catch (Exception e) {
            e.printStackTrace();
        }

        listAdapter = new KeyRecyclerAdapter();
        View viewHeader = View.inflate(this, R.layout.activity_main_header, null);

        mListView.addHeaderView(viewHeader);
        listAdapter = new KeyRecyclerAdapter(this, R.id.keyAlias);
    }


    public void refreshKeys() {

        mKeyAliases = new ArrayList<>();

        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                mKeyAliases.add(aliases.nextElement());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }

    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    public void createNewKeys(View view) {

        Calendar end, start = null;
        String alias = mAliasText.getText().toString();
        try {
            if (!keyStore.containsAlias(alias))
                start = Calendar.getInstance();
            end = Calendar.getInstance();

            end.add(Calendar.YEAR, 1);

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                    .setKeyValidityStart(start.getTime())
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setKeyValidityEnd(end.getTime())
                    .build();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);

            KeyPair keyPair = generator.generateKeyPair();
        } catch (Exception ex) {

            Toast.makeText(this, "Exception " + ex.getMessage() + " occured", Toast.LENGTH_LONG).show();

            Log.e(TAG, Log.getStackTraceString(ex));

        }

        refreshKeys();
    }


    public void deleteKey(final String alias){

        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + alias + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {

                try {
                    keyStore.deleteEntry(alias);
                    refreshKeys();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                    Toast.makeText(MainActivity.this,
                            "Exception " + e.getMessage() + " occured",
                            Toast.LENGTH_LONG).show();
                    Log.e(TAG, Log.getStackTraceString(e));

                }
                dialog.dismiss();

            }
        })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .create();

        alertDialog.show();
    }


    public void encryptString(String alias) {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            String initialText = mStartText.getText().toString();
            if (initialText.isEmpty()) {
                Toast.makeText(this, "Enter text in the 'Initial Text' widget", Toast.LENGTH_LONG).show();
                return;
            }

            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            inCipher.init(Cipher.DECRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,inCipher);
            cipherOutputStream.write(initialText.getBytes("UTF-8"));
            cipherOutputStream.close();
            


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}
