package com.android.internal.util.framework;

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
import org.lsposed.lsparanoid.Obfuscate;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;

@Obfuscate
public final class Android {
    private static final String TAG = "chiteroman";
    private static final PrivateKey EC, RSA;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final HashMap<String, String> map = new HashMap<>();
    private static final String EC_PRIVATE_KEY = """
            """;
    private static final String RSA_PRIVATE_KEY = """
            """;

    static {
        map.put("MANUFACTURER", "");
        map.put("BRAND", "");
        map.put("DEVICE", "");
        map.put("PRODUCT", "");
        map.put("MODEL", "");
        map.put("FINGERPRINT", "");

        try (PEMParser parser = new PEMParser(new StringReader(EC_PRIVATE_KEY))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            EC = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            Log.e(TAG, e.toString());
            throw new RuntimeException(e);
        }

        try (PEMParser parser = new PEMParser(new StringReader(RSA_PRIVATE_KEY))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            RSA = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            Log.e(TAG, e.toString());
            throw new RuntimeException(e);
        }
    }

    public static Certificate modifyCertificate(Certificate certificate) {
        if (certificate == null) return null;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());

            Extension ext = holder.getExtension(OID);

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

            SecureRandom random = new SecureRandom();

            byte[] verifiedBootKey = new byte[32];
            byte[] verifiedBootHash = new byte[32];

            random.nextBytes(verifiedBootKey);
            random.nextBytes(verifiedBootHash);

            ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

            vector.add(rootOfTrustTagObj);

            ASN1Sequence hackTeeEnforced = new DERSequence(vector);

            encodables[7] = hackTeeEnforced;

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(holder).replaceExtension(hackedExt);

            X509Certificate x509Certificate = new JcaX509CertificateConverter().getCertificate(holder);

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
            Log.e(TAG, t.toString());
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
                        Log.e(TAG, t.toString());
                    }
                });
            } catch (Throwable t) {
                Log.e(TAG, t.toString());
            }
        }
    }
}