package com.android.internal.util.framework;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyProperties;
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
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.lsposed.lsparanoid.Obfuscate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

@Obfuscate
public final class Android {
    private static final String TAG = "chiteroman";
    private static final PEMKeyPair EC, RSA;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final HashMap<String, String> map = new HashMap<>();
    private static final List<Certificate> EC_CERTS = new ArrayList<>();
    private static final List<Certificate> RSA_CERTS = new ArrayList<>();
    private static volatile boolean isGmsUnstable = false;

    static {
        map.put("MANUFACTURER", "motorola");
        map.put("BRAND", "motorola");
        map.put("DEVICE", "clark");
        map.put("PRODUCT", "clark_retus");
        map.put("MODEL", "XT1575");
        map.put("FINGERPRINT", "motorola/clark_retus/clark:6.0/MPHS24.49-18-8/4:user/release-keys");

        try {
            EC = parseKeyPair(Keybox.EC.PRIVATE_KEY);
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_1));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_2));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_3));

            RSA = parseKeyPair(Keybox.RSA.PRIVATE_KEY);
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_1));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_2));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_3));
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }
        return new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(pemObject.getContent()));
    }

    public static byte[] certificateChain(byte[] bytes) {
        if (bytes == null) return null;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            LinkedList<Certificate> certificates = new LinkedList<>(factory.generateCertificates(new ByteArrayInputStream(bytes)));

            X509Certificate x509Certificate = (X509Certificate) certificates.getFirst();

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            if (KeyProperties.KEY_ALGORITHM_EC.equals(x509Certificate.getPublicKey().getAlgorithm())) {
                for (Certificate c : EC_CERTS) {
                    byteArrayOutputStream.write(c.getEncoded());
                }
            } else {
                for (Certificate c : RSA_CERTS) {
                    byteArrayOutputStream.write(c.getEncoded());
                }
            }

            return byteArrayOutputStream.toByteArray();

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return bytes;
    }

    public static byte[] certificate(byte[] bytes) {
        if (bytes == null) return null;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(bytes);

            if (!"CN=Android Keystore Key".equals(holder.getSubject().toString())) return bytes;

            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);

            Extension ext = holder.getExtension(OID);

            if (ext == null) return bytes;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = new ASN1EncodableVector(teeEnforced.size());
            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

                int tag = taggedObject.getTagNo();

                if (isGmsUnstable)
                    if (tag == 710 || tag == 711 || tag == 712 || tag == 716 || tag == 717)
                        continue;

                if (tag == 704) continue;
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

            ASN1Sequence hackEnforced = new DERSequence(vector);

            encodables[7] = hackEnforced;

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            if (!isGmsUnstable && KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(EC_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(EC.getPrivateKeyInfo()));
            } else {
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(RSA_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder("SHA256withRSA").build(new JcaPEMKeyConverter().getPrivateKey(RSA.getPrivateKeyInfo()));
            }

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            builder.addExtension(hackedExt);

            return builder.build(signer).getEncoded();

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return bytes;
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        if (caList == null) return null;
        if (caList.length < 4) return caList;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(caList[0].getEncoded());

            if (!"CN=Android Keystore Key".equals(holder.getSubject().toString())) return caList;

            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);

            Extension ext = holder.getExtension(OID);

            if (ext == null) return caList;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = new ASN1EncodableVector(teeEnforced.size());
            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

                int tag = taggedObject.getTagNo();

                if (isGmsUnstable)
                    if (tag == 710 || tag == 711 || tag == 712 || tag == 716 || tag == 717)
                        continue;

                if (tag == 704) continue;
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

            ASN1Sequence hackEnforced = new DERSequence(vector);

            encodables[7] = hackEnforced;

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            LinkedList<Certificate> certs;

            if (!isGmsUnstable && KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                certs = new LinkedList<>(EC_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(EC_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(EC.getPrivateKeyInfo()));
            } else {
                certs = new LinkedList<>(RSA_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(RSA_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder("SHA256withRSA").build(new JcaPEMKeyConverter().getPrivateKey(RSA.getPrivateKeyInfo()));
            }

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            builder.addExtension(hackedExt);

            certs.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            return certs.toArray(Certificate[]::new);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
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

    public static void newApplication(Context context) {
        if (context == null) return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (packageName != null && processName != null && packageName.equals("com.google.android.gms") && processName.equals("com.google.android.gms.unstable")) {
            isGmsUnstable = true;
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

    public static void onEngineGetCertificateChain() {
        isGmsUnstable = Arrays.stream(Thread.currentThread().getStackTrace()).anyMatch(e -> e.getClassName().toLowerCase(Locale.US).contains("droidguard"));
    }

    public static boolean hasSystemFeature(boolean ret, String feature) {
        if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(feature)) {
            return false;
        }
        return ret;
    }
}