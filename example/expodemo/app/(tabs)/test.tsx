import { StyleSheet, TextInput, TouchableOpacity, ScrollView } from 'react-native';
import { Link } from 'expo-router';
import React, { useState } from 'react';

import { ThemedView } from '@/components/themed-view';
import { ThemedText } from '@/components/themed-text';
import * as Unsea from 'unsea';

export default function TestScreen() {
  const [keys, setKeys] = useState<any | null>(null);
  const [input, setInput] = useState<string>('Hello, Unsea!');
  const [cipher, setCipher] = useState<any | null>(null);
  const [plain, setPlain] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function toJson(value: any) {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  async function handleGenerateKeys() {
    try {
      const kp = await Unsea.generateRandomPair();
      setKeys(kp);
      setCipher(null);
      setPlain(null);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleEncrypt() {
    try {
      if (!keys?.epub) {
        setError('请先生成密钥对');
        return;
      }
      const payload = await Unsea.encryptMessageWithMeta(input, { epub: keys.epub });
      setCipher(payload);
      setPlain(null);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleDecrypt() {
    try {
      if (!cipher) {
        setError('请先加密数据');
        return;
      }
      if (!keys?.epriv) {
        setError('缺少解密私钥，请先生成密钥对');
        return;
      }
      const text = await Unsea.decryptMessageWithMeta(cipher, keys.epriv);
      setPlain(text);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <ScrollView style={styles.scroll} contentContainerStyle={styles.container}>
      <ThemedView style={styles.content}>
      <ThemedText type="title">Unsea for native</ThemedText>
      <ThemedText style={styles.paragraph}>
        
      </ThemedText>
      <TextInput
        style={styles.input}
        placeholder="输入要加密的文本"
        value={input}
        onChangeText={setInput}
      />
      <ThemedView style={styles.row}>
        <TouchableOpacity onPress={handleGenerateKeys} style={styles.button}>
          <ThemedText type="link">随机生成密钥</ThemedText>
        </TouchableOpacity>
        <TouchableOpacity onPress={handleEncrypt} style={styles.button}>
          <ThemedText type="link">加密</ThemedText>
        </TouchableOpacity>
        <TouchableOpacity onPress={handleDecrypt} style={styles.button}>
          <ThemedText type="link">解密</ThemedText>
        </TouchableOpacity>
      </ThemedView>
      {error && <ThemedText style={styles.error}>{error}</ThemedText>}
      {keys && (
        <ThemedView style={styles.block}>
          <ThemedText type="subtitle">密钥对</ThemedText>
          <ThemedText>{toJson(keys)}</ThemedText>
        </ThemedView>
      )}
      {cipher && (
        <ThemedView style={styles.block}>
          <ThemedText type="subtitle">密文与元信息</ThemedText>
          <ThemedText>{toJson(cipher)}</ThemedText>
        </ThemedView>
      )}
      {plain && (
        <ThemedView style={styles.block}>
          <ThemedText type="subtitle">解密结果</ThemedText>
          <ThemedText>{plain}</ThemedText>
        </ThemedView>
      )}
      <Link href="/" style={styles.link}>
        <ThemedText type="link">返回首页</ThemedText>
      </Link>
      </ThemedView>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: { flex: 1,backgroundColor:'#fff' },
  container: { padding: 0, gap: 12 },
  content: { alignItems: 'center', gap: 12,margin:20 },
  paragraph: {
    textAlign: 'center',
  },
  input: {
    width: '100%',
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  row: {
    flexDirection: 'row',
    gap: 12,
  },
  button: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderWidth: 1,
    borderRadius: 8,
    borderColor: '#888',
  },
  block: {
    width: '100%',
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    gap: 6,
  },
  error: {
    color: 'red',
  },
  link: {
    marginTop: 16,
    paddingVertical: 12,
  },
});
