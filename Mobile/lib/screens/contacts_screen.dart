import 'package:flutter/material.dart';

class ContactsScreen extends StatelessWidget {
  const ContactsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      decoration: InputDecoration(
                        hintText: 'Search contacts...',
                        prefixIcon: const Icon(Icons.search_rounded),
                        filled: true,
                        fillColor: const Color(0xFFF1F5F9),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  ElevatedButton.icon(
                    onPressed: () {},
                    icon: const Icon(Icons.person_add_rounded, size: 16),
                    label: const Text('Add'),
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView.builder(
                itemCount: 0,
                itemBuilder: (ctx, i) => const SizedBox(),
              ),
            ),
            const Center(child: Padding(
              padding: EdgeInsets.all(40),
              child: Column(
                children: [
                  Icon(Icons.contacts_rounded, size: 48, color: Color(0xFFCBD5E1)),
                  SizedBox(height: 12),
                  Text('No contacts yet', style: TextStyle(color: Color(0xFF94A3B8))),
                  Text('Add a contact or import from SIM', style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12)),
                ],
              ),
            )),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showAddContact(context),
        backgroundColor: const Color(0xFF2563EB),
        child: const Icon(Icons.person_add_rounded, color: Colors.white),
      ),
    );
  }

  void _showAddContact(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(ctx).viewInsets.bottom, left: 20, right: 20, top: 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('New Contact', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 16),
            const TextField(decoration: InputDecoration(labelText: 'Name')),
            const SizedBox(height: 10),
            const TextField(decoration: InputDecoration(labelText: 'Number'), keyboardType: TextInputType.phone),
            const SizedBox(height: 20),
            SizedBox(width: double.infinity,
              child: ElevatedButton(onPressed: () => Navigator.pop(ctx), child: const Text('Save'))),
            const SizedBox(height: 10),
          ],
        ),
      ),
    );
  }
}
