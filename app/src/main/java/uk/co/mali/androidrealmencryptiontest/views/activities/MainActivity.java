package uk.co.mali.androidrealmencryptiontest.views.activities;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

import butterknife.BindView;
import butterknife.ButterKnife;
import uk.co.mali.androidrealmencryptiontest.R;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String CIPHER_TYPE = "RSA/ECB/PKCS1PADDING";
    private static final String CIPHER_PROVIDER = "AndroidOpenSSL";

  //  @BindView(R.id.aliasText)
    EditText mAliasText;

  //  @BindView(R.id.startText)
    EditText mStartText;

 //   @BindView(R.id.decryptedText)
    EditText mDecryptText;

 //   @BindView(R.id.encryptedText)
    EditText mEncryptedText;

  //  @BindView(R.id.listView)
    ListView mListView;

    private KeyRecyclerAdapter listAdapter;

    KeyStore keyStore;

    public List<String> mKeyAliases ;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

        } catch (Exception e) {
            e.printStackTrace();
        }
        refreshKeys();
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        View viewHeader = View.inflate(this, R.layout.activity_main_header, null);




        listAdapter = new KeyRecyclerAdapter(this, R.id.keyAlias);
        mAliasText = (EditText) viewHeader.findViewById(R.id.aliasText);
        mStartText = (EditText) viewHeader.findViewById(R.id.startText);
        mDecryptText = (EditText)viewHeader.findViewById(R.id.decryptedText);
        mEncryptedText = (EditText) viewHeader.findViewById(R.id.encryptedText);
        mListView = (ListView) findViewById(R.id.listView);



        mListView.addHeaderView(viewHeader);
        listAdapter = new KeyRecyclerAdapter(this,R.id.keyAlias);
        mListView.setAdapter(listAdapter);


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

        Calendar end=null, start = null;
        String alias = mAliasText.getText().toString();
        Log.d(TAG,"Alias Text in Create New Keys, : "+alias);

        try {
         //   int keystoreSize = keyStore.size();

                if (!keyStore.containsAlias(alias)) {
                    start = Calendar.getInstance();
                    end = Calendar.getInstance();
                    end.add(Calendar.YEAR, 1);

                    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .setCertificateSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                            .setKeyValidityStart(start.getTime())
                            .setCertificateSerialNumber(BigInteger.ONE)
                            .setKeyValidityEnd(end.getTime())
                            .build();

                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                    generator.initialize(spec);

                    KeyPair keyPair = generator.generateKeyPair();

                }




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
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,inCipher);
            cipherOutputStream.write(initialText.getBytes("UTF-8"));

            cipherOutputStream.close();
            byte [] vals = outputStream.toByteArray();

          //  String m = Base64.encodeToString(vals,Base64.DEFAULT);

            mEncryptedText.setText(Base64.encodeToString(vals,Base64.DEFAULT));


        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }

    }

    public void decryptString(String alias){

        try {
            KeyStore.PrivateKeyEntry privateKeyEntry= (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            String cipherText = mEncryptedText.getText().toString();
            CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(Base64.decode(cipherText,Base64.DEFAULT)),output);

        ArrayList<Byte> values = new ArrayList<>();

        int nextByte;

        while((nextByte = cipherInputStream.read())!= -1){
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];

        for(int i = 0; i<bytes.length;i++){
            bytes[i] = values.get(i).byteValue();
        }

        String finalText = new String(bytes,0,bytes.length,"UTF-8");
        mDecryptText.setText(finalText);

    } catch (Exception e) {
        Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
        Log.e(TAG, Log.getStackTraceString(e));
    }
    }

    public class KeyRecyclerAdapter extends ArrayAdapter<String> {
        public KeyRecyclerAdapter(Context context, int textView) {
            super(context, textView);
        }

        @BindView(R.id.encryptButton)
        Button encryptButton;
        @BindView(R.id.decryptButton)
        Button decryptButton;
        @BindView(R.id.keyAlias)
        TextView keyAlias;

        @Override
        public int getCount() {
            return mKeyAliases.size();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View itemView = LayoutInflater.from(parent.getContext()).
                    inflate(R.layout.list_item, parent, false);
            ButterKnife.bind(this,itemView);

           // final TextView keyAlias = (TextView) itemView.findViewById(R.id.keyAlias);
            keyAlias.setText(mKeyAliases.get(position));
           // Button encryptButton = (Button) itemView.findViewById(R.id.encryptButton);
            encryptButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    encryptString(keyAlias.getText().toString());
                }
            });
           // Button decryptButton = (Button) itemView.findViewById(R.id.decryptButton);
            decryptButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    decryptString(keyAlias.getText().toString());
                }
            });
            final Button deleteButton = (Button) itemView.findViewById(R.id.deleteButton);
            deleteButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    deleteKey(keyAlias.getText().toString());
                }
            });

            return itemView;
        }

        @Override
        public String getItem(int position) {
            return mKeyAliases.get(position);
        }
    }


}
