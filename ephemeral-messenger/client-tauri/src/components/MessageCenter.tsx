import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '../services/api';
import { Identity, Message, Contact, EncryptMessageRequest, DecryptMessageRequest } from '../types';
import SessionManager from './SessionManager';
import './MessageCenter.css';

interface MessageCenterProps {
  identity: Identity;
  onError: (error: string) => void;
}

const MessageCenter: React.FC<MessageCenterProps> = ({ identity, onError }) => {
  const [activeTab, setActiveTab] = useState<'direct' | 'sessions'>('direct');
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [newContactFingerprint, setNewContactFingerprint] = useState('');
  const [newContactName, setNewContactName] = useState('');
  const [sessionMessages, setSessionMessages] = useState<{[sessionId: string]: Message[]}>({});
  const [activeSession, setActiveSession] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadContacts();
  }, []);

  useEffect(() => {
    if (selectedContact) {
      loadMessages(selectedContact.fingerprint);
    }
  }, [selectedContact]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadContacts = async () => {
    try {
      const contactList = await invoke<Contact[]>('get_contacts');
      setContacts(contactList);
    } catch (error) {
      console.log('No contacts found');
    }
  };

  const loadMessages = async (contactFingerprint: string) => {
    try {
      const messageList = await invoke<Message[]>('get_messages', {
        contactFingerprint,
      });
      setMessages(messageList);
    } catch (error) {
      console.log('No messages found');
      setMessages([]);
    }
  };

  const addContact = async () => {
    if (!newContactFingerprint.trim() || !newContactName.trim()) {
      onError('Contact fingerprint and name are required');
      return;
    }

    try {
      const contact: Contact = {
        fingerprint: newContactFingerprint.trim(),
        name: newContactName.trim(),
        public_key: '', // Will be resolved when first message is sent
      };

      await invoke('add_contact', { contact });
      await loadContacts();

      setNewContactFingerprint('');
      setNewContactName('');
      setShowAddContact(false);
    } catch (error) {
      onError(`Failed to add contact: ${error}`);
    }
  };

  const sendMessage = async () => {
    if (activeTab === 'sessions' && activeSession) {
      return sendSessionMessage();
    }

    if (!selectedContact || !newMessage.trim() || !passphrase) {
      onError('Please select a contact, enter a message, and provide passphrase');
      return;
    }

    try {
      setIsSending(true);

      const encryptRequest: EncryptMessageRequest = {
        message: newMessage.trim(),
        recipient_public_key: selectedContact.public_key || selectedContact.fingerprint,
        passphrase,
      };

      const encryptedMessage = await invoke('encrypt_message', encryptRequest);

      // In a real implementation, this would be sent over the network
      // For now, we'll just add it to local messages
      const message: Message = {
        id: Date.now().toString(),
        sender_fingerprint: identity.fingerprint,
        recipient_fingerprint: selectedContact.fingerprint,
        content: newMessage.trim(),
        timestamp: Date.now(),
        encrypted_content: JSON.stringify(encryptedMessage),
      };

      await invoke('store_message', { message });
      await loadMessages(selectedContact.fingerprint);

      setNewMessage('');
      setPassphrase('');

    } catch (error) {
      onError(`Failed to send message: ${error}`);
    } finally {
      setIsSending(false);
    }
  };

  const sendSessionMessage = async () => {
    if (!activeSession || !newMessage.trim()) {
      onError('Please select a session and enter a message');
      return;
    }

    try {
      setIsSending(true);

      const response = await invoke('encrypt_session_message', {
        session_id: activeSession,
        plaintext: newMessage.trim(),
      });

      if (response.success) {
        // Add to local session messages
        const message: Message = {
          id: Date.now().toString(),
          sender_fingerprint: identity.fingerprint,
          recipient_fingerprint: activeSession,
          content: newMessage.trim(),
          timestamp: Date.now(),
          encrypted_content: JSON.stringify(response.data),
        };

        setSessionMessages(prev => ({
          ...prev,
          [activeSession]: [...(prev[activeSession] || []), message]
        }));

        setNewMessage('');
      } else {
        onError(response.error || 'Failed to encrypt session message');
      }

    } catch (error) {
      onError(`Failed to send session message: ${error}`);
    } finally {
      setIsSending(false);
    }
  };

  const decryptMessage = async (message: Message): Promise<string> => {
    if (message.sender_fingerprint === identity.fingerprint) {
      return message.content; // Own messages are stored decrypted
    }

    try {
      const encryptedData = JSON.parse(message.encrypted_content);
      const decryptRequest: DecryptMessageRequest = {
        encrypted_message: encryptedData,
        passphrase,
      };

      const decrypted = await invoke<string>('decrypt_message', decryptRequest);
      return decrypted;
    } catch (error) {
      return '[Encrypted - Enter passphrase to decrypt]';
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays === 1) {
      return 'Yesterday';
    } else if (diffDays < 7) {
      return date.toLocaleDateString([], { weekday: 'short' });
    } else {
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }
  };

  return (
    <div className="message-center">
      <div className="message-center-header">
        <div className="message-tabs">
          <button
            className={`tab-button ${activeTab === 'direct' ? 'active' : ''}`}
            onClick={() => setActiveTab('direct')}
          >
            🔗 Direct Messages
          </button>
          <button
            className={`tab-button ${activeTab === 'sessions' ? 'active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            🔐 Cipher Sessions
          </button>
        </div>
      </div>

      {activeTab === 'direct' && (
        <div className="message-center-content">
          <div className="contacts-sidebar">
        <div className="contacts-header">
          <h3>Contacts</h3>
          <button
            onClick={() => setShowAddContact(true)}
            className="add-contact-button"
          >
            +
          </button>
        </div>

        <div className="contacts-list">
          {contacts.map((contact) => (
            <div
              key={contact.fingerprint}
              className={`contact-item ${selectedContact?.fingerprint === contact.fingerprint ? 'active' : ''}`}
              onClick={() => setSelectedContact(contact)}
            >
              <div className="contact-name">{contact.name}</div>
              <div className="contact-fingerprint">
                {contact.fingerprint.slice(0, 8)}...
              </div>
            </div>
          ))}
        </div>

        {contacts.length === 0 && (
          <div className="no-contacts">
            No contacts yet. Add a contact to start messaging.
          </div>
        )}
      </div>

      <div className="messages-main">
        {selectedContact ? (
          <>
            <div className="messages-header">
              <h3>{selectedContact.name}</h3>
              <span className="contact-fingerprint">
                {selectedContact.fingerprint}
              </span>
            </div>

            <div className="messages-container">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`message ${message.sender_fingerprint === identity.fingerprint ? 'sent' : 'received'}`}
                >
                  <div className="message-content">
                    {message.sender_fingerprint === identity.fingerprint
                      ? message.content
                      : '[Encrypted - Need passphrase to decrypt]'
                    }
                  </div>
                  <div className="message-timestamp">
                    {formatTimestamp(message.timestamp)}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            <div className="message-input-container">
              <div className="passphrase-input-container">
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Encryption passphrase..."
                  className="passphrase-input small"
                />
              </div>
              <div className="message-input-group">
                <textarea
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  placeholder="Type your encrypted message..."
                  className="message-input"
                  rows={3}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      sendMessage();
                    }
                  }}
                />
                <button
                  onClick={sendMessage}
                  disabled={isSending || !newMessage.trim() || !passphrase}
                  className="send-button"
                >
                  {isSending ? '🔒' : '📤'}
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="no-contact-selected">
            <h3>Select a contact to start messaging</h3>
            <p>All messages are encrypted end-to-end with triple encryption layers.</p>
          </div>
        )}
      </div>
        </div>
      )}

      {showAddContact && (
        <div className="add-contact-overlay">
          <div className="add-contact-dialog">
            <h3>Add Contact</h3>

            <div className="form-group">
              <label>Contact Name</label>
              <input
                type="text"
                value={newContactName}
                onChange={(e) => setNewContactName(e.target.value)}
                placeholder="Enter contact name..."
              />
            </div>

            <div className="form-group">
              <label>Public Key Fingerprint</label>
              <input
                type="text"
                value={newContactFingerprint}
                onChange={(e) => setNewContactFingerprint(e.target.value)}
                placeholder="Enter contact's fingerprint..."
              />
            </div>

            <div className="dialog-actions">
              <button
                onClick={() => setShowAddContact(false)}
                className="cancel-button"
              >
                Cancel
              </button>
              <button
                onClick={addContact}
                className="add-button primary"
                disabled={!newContactName.trim() || !newContactFingerprint.trim()}
              >
                Add Contact
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'sessions' && (
        <SessionManager
          onError={onError}
          onSessionCreated={(sessionId) => setActiveSession(sessionId)}
          onSessionJoined={(sessionId) => setActiveSession(sessionId)}
          activeSession={activeSession}
          sessionMessages={sessionMessages}
          onSendMessage={(sessionId, message) => {
            setActiveSession(sessionId);
            setNewMessage(message);
            sendSessionMessage();
          }}
        />
      )}
    </div>
  );
};

export default MessageCenter;