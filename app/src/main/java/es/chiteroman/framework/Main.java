package es.chiteroman.framework;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.concurrent.ThreadLocalRandom;

public class Main {
    private static final PrivateKey EC, RSA;
    private static final HashMap<String, String> map = new HashMap<>();

    static {
        modifyCertificate(null);
        onNewApp(null);

        map.put("MANUFACTURER", "");
        map.put("BRAND", "");
        map.put("DEVICE", "");
        map.put("PRODUCT", "");
        map.put("MODEL", "");
        map.put("FINGERPRINT", "");

        String ec = """
                -----BEGIN EC PRIVATE KEY-----
                -----END EC PRIVATE KEY-----""";

        String rsa = """
                -----BEGIN RSA PRIVATE KEY-----
                -----END RSA PRIVATE KEY-----""";

        try (PEMParser parser = new PEMParser(new StringReader(ec))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            EC = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            Log.e("chiteroman", e.toString());
            throw new RuntimeException(e);
        }

        try (PEMParser parser = new PEMParser(new StringReader(rsa))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            RSA = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            Log.e("chiteroman", e.toString());
            throw new RuntimeException(e);
        }
    }

    public static Certificate modifyCertificate(Certificate certificate) {
        if (!(certificate instanceof X509Certificate x509Certificate)) return certificate;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(x509Certificate.getEncoded());

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

            Extension ext = holder.getExtension(oid);

            if (ext == null) return certificate;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = new ASN1EncodableVector(teeEnforced.size());
            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) continue;
                vector.add(taggedObject);
            }

            byte[] verifiedBootKey = new byte[32];
            byte[] verifiedBootHash = new byte[32];

            ThreadLocalRandom.current().nextBytes(verifiedBootKey);
            ThreadLocalRandom.current().nextBytes(verifiedBootHash);

            ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

            vector.add(rootOfTrustTagObj);

            ASN1Sequence hackTeeEnforced = new DERSequence(vector);

            encodables[7] = hackTeeEnforced;

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(oid, false, hackedSeqOctets);

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(holder).replaceExtension(hackedExt);

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(x509Certificate.getSigAlgName());

            ContentSigner signer;

            if (x509Certificate.getSigAlgName().contains("ECDSA")) {
                signer = signerBuilder.build(EC);
            } else {
                signer = signerBuilder.build(RSA);
            }

            X509CertificateHolder hackedCert = builder.build(signer);

            return new JcaX509CertificateConverter().getCertificate(hackedCert);

        } catch (Throwable t) {
            Log.e("chiteroman", t.toString());
        }
        return certificate;
    }

    private static Field getFieldByName(String name) {

        Field field;
        try {
            field = Build.class.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            try {
                field = Build.VERSION.class.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                return null;
            }
        }

        field.setAccessible(true);

        return field;
    }

    public static void onNewApp(Context context) {
        if (context == null) return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (packageName == null || processName == null) return;

        if (packageName.equals("com.google.android.gms") && processName.equals("com.google.android.gms.unstable")) {
            try {
                map.forEach((s, s2) -> {
                    Field field = getFieldByName(s);
                    if (field == null) return;
                    try {
                        field.set(null, s2);
                    } catch (Throwable t) {
                        Log.e("chiteroman", t.toString());
                    }
                });
            } catch (Throwable t) {
                Log.e("chiteroman", t.toString());
            }
        }
    }
}