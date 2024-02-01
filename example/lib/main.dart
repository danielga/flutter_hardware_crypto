import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:flutter/material.dart';
import 'package:hardware_crypto/hardware_crypto.g.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

void doStuff(HardwareCryptoApi hardwareCryptoPlugin) async {
  const key = """-----BEGIN PRIVATE KEY-----
INSERT PRIVATE KEY HERE
-----END PRIVATE KEY-----
""";
  await hardwareCryptoPlugin.deleteKeyPair("test");
  await hardwareCryptoPlugin.importPEMKey("test", key);
  final bytes = await hardwareCryptoPlugin.exportPublicKey("test");
  print(hex.encode(bytes));
  var signature =
      await hardwareCryptoPlugin.sign("test", utf8.encode('Hello world!'));
  print(hex.encode(signature));
}

class AppContent extends StatelessWidget {
  final _hardwareCryptoPlugin = HardwareCryptoApi();

  AppContent({super.key}) {
    doStuff(_hardwareCryptoPlugin);
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: TextButton(
        onPressed: () async {
          var bytes = utf8.encode('Hello world!');
          var signature = await _hardwareCryptoPlugin.sign("test", bytes);
          var snackBar = SnackBar(
            content: Text(
                'Successfully signed message: signature length ${signature.length}'),
          );
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(snackBar);
          }
        },
        child: const Text('Sign with biometrics'),
      ),
    );
  }
}

class _MyAppState extends State<MyApp> {
  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
          appBar: AppBar(
            title: const Text('Plugin example app'),
          ),
          body: AppContent()),
    );
  }
}
