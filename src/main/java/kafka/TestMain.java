package kafka;

import kafka.packager.GsPackager;
import kafka.security.SecurityUtil;
import kafka.security.StringUtil;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.jpos.iso.ISOException;
import org.jpos.iso.ISOMsg;
import org.jpos.iso.ISOUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static kafka.security.SecurityUtil.encryptAES;

/**
 * Created by A_Tofigh at 09/12/2024
 */
public class TestMain {

    private static String BROKER_LIST;
    private static String REQ_TOPIC;
    private static String RES_TOPIC;
    private static String CONSUMER_GROUP_NAME;
    private static long testDelay;
    private static Map<String, Integer> pts = new HashMap<>();
    private static String ptsStr;

    static Producer<String, String> producer;
    static KafkaConsumer<String, String> consumer;
    static byte[] exchangedKey;

    static {
        System.out.println("initial data.................");
        try {
            Properties config = new Properties();
            InputStream inputStream = Files.newInputStream(Paths.get("config.properties"));
            config.load(inputStream);
            inputStream.close();
            BROKER_LIST = config.getProperty("brokers");
            REQ_TOPIC = config.getProperty("req-topic");
            RES_TOPIC = config.getProperty("res-topic");
            CONSUMER_GROUP_NAME = config.getProperty("consumer-group-name");
            testDelay = Long.parseLong(config.getProperty("test-delay")) * 1000;
            ptsStr = config.getProperty("pts");
            if (ptsStr != null) {
                String[] ptsArr = ptsStr.split(";");
                Arrays.stream(ptsArr).forEach(data -> {
                    String[] item = data.split(":");
                    pts.put(item[0], Integer.parseInt(item[1]));
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, BROKER_LIST);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producer = new KafkaProducer<>(props);

        props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, BROKER_LIST);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, CONSUMER_GROUP_NAME);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        consumer = new KafkaConsumer<>(props);
    }


    public static void main(String[] args) {
        List<String> topics = new ArrayList();
        topics.add(REQ_TOPIC);
        consumer.subscribe(topics);
        while (true) {
            try {
                if (testDelay > 0) {
                    System.out.println("waiting for: " + testDelay);
                    Thread.sleep(testDelay);
                }
                ConsumerRecords<String, String> records = consumer.poll(100);
                for (ConsumerRecord<String, String> record : records) {
                    String message = record.value();
                    System.out.println("key: " + record.key() + " --- value: " + message);
                    ISOMsg iso = new ISOMsg();
                    iso.setPackager(new GsPackager());
                    iso.unpack(message.getBytes());
                    String pt = iso.getString(5);
                    ISOMsg response = iso.clone("0", "2", "3", "4", "5", "6", "15");
                    response.setResponseMTI();
                    if (iso.getString(3).equals("800000")) {
                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(128);
                        SecretKey key = keyGenerator.generateKey();
                        exchangedKey = key.getEncoded();
                        response.set(39, "00");
                        response.set(63,
                                encryptAES(exchangedKey, ISOUtil.hex2byte("44444444444444444444444444444444")));
                        response.set(64, SecurityUtil.computeGsMessageMac(response, ISOUtil.hex2byte("44444444444444444444444444444444")));
                    } else if (iso.getString(3).equals("200000")) {
                        int ttc = Integer.parseInt(iso.getString(15));
                        int lastTtc = pts.get(pt);
                        int nextTtc;
                        if (lastTtc == 0) {
                            nextTtc = 1;
                            pts.put(pt, nextTtc);
                            response.set(39, "00");
                        } else if (lastTtc == ttc) {
                            nextTtc = ++ttc;
                            response.set(39, "94");
                        } else {
                            nextTtc = ++ttc;
                            pts.put(pt, nextTtc);
                            response.set(39, "00");
                        }
                        response.set(15, StringUtil.fixWidthZeroPad(nextTtc, 12));
                        if (exchangedKey != null)
                            response.set(64, SecurityUtil.computeGsMessageMac(response, exchangedKey));
                        else {
                            System.out.println("this mg don't have done keyExchange yet!");
                            response.set(39, "63");
                        }
                    } else if (iso.getString(3).equals("100000")) {
                        if (pt.equals("00")) {
                            StringBuilder inquiry = new StringBuilder();
                            for (Map.Entry<String, Integer> entry : pts.entrySet()) {
                                inquiry
                                        .append(entry.getKey())
                                        .append(":")
                                        .append(entry.getValue());
                                inquiry.append(";");
                            }
                            inquiry.deleteCharAt(inquiry.lastIndexOf(";"));
                            response.set(33, inquiry.toString());
                        } else {
                            int laseTtc = pts.get(pt);
                            response.set(33, laseTtc != 0 ? (pt + ":" + laseTtc) : (pt + ":1"));
                        }
                        response.set(39, "00");
                        if (exchangedKey != null)
                            response.set(64, SecurityUtil.computeGsMessageMac(response, exchangedKey));
                    }
                    prod(record.key(), new String(response.pack()));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void prod(String key, String message) {
        ProducerRecord<String, String> record = new ProducerRecord<>(RES_TOPIC, key, message);
        producer.send(record, (metadata, exception) -> {
            if (exception == null) {
                System.out.println("Message {" + message + "} was sent successfully");
            } else {
                System.out.println(exception.getMessage());
            }
        });
    }
}
