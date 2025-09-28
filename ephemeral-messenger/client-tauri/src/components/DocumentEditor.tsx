import React, { useState, useEffect, useRef } from 'react';
import { EditorState } from 'prosemirror-state';
import { EditorView } from 'prosemirror-view';
import { Schema, DOMParser } from 'prosemirror-model';
import { schema } from 'prosemirror-schema-basic';
import { addListNodes } from 'prosemirror-schema-list';
import { exampleSetup } from 'prosemirror-example-setup';
import { invoke, save } from '../services/api';
import { Identity, CreateDocumentRequest, DocumentPolicy } from '../types';
import './DocumentEditor.css';

interface DocumentEditorProps {
  identity: Identity;
  onError: (error: string) => void;
}

const DocumentEditor: React.FC<DocumentEditorProps> = ({ identity, onError }) => {
  const editorRef = useRef<HTMLDivElement>(null);
  const [editorView, setEditorView] = useState<EditorView | null>(null);
  const [documentTitle, setDocumentTitle] = useState('Untitled Document');
  const [recipients, setRecipients] = useState<string[]>([]);
  const [newRecipient, setNewRecipient] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [policy, setPolicy] = useState<DocumentPolicy>({
    auto_expire_hours: undefined,
    max_open_count: undefined,
    offline_open_allowed: true,
    require_hardware_token: false,
    watermark_enabled: false,
  });

  // Create ProseMirror schema with list support
  const mySchema = new Schema({
    nodes: addListNodes(schema.spec.nodes, 'paragraph block*', 'block'),
    marks: schema.spec.marks,
  });

  useEffect(() => {
    if (editorRef.current && !editorView) {
      const state = EditorState.create({
        schema: mySchema,
        plugins: exampleSetup({ schema: mySchema }),
      });

      const view = new EditorView(editorRef.current, {
        state,
        dispatchTransaction: (transaction) => {
          const newState = view.state.apply(transaction);
          view.updateState(newState);
        },
      });

      setEditorView(view);

      return () => {
        view.destroy();
      };
    }
  }, [editorRef.current]);

  const getDocumentContent = (): string => {
    if (!editorView) return '';

    const doc = editorView.state.doc;
    const div = document.createElement('div');
    div.appendChild(DOMParser.fromSchema(mySchema).serializeFragment(doc.content));
    return div.innerHTML;
  };

  const addRecipient = () => {
    const trimmed = newRecipient.trim();
    if (trimmed && !recipients.includes(trimmed)) {
      setRecipients([...recipients, trimmed]);
      setNewRecipient('');
    }
  };

  const removeRecipient = (recipient: string) => {
    setRecipients(recipients.filter(r => r !== recipient));
  };

  const handleSaveDocument = async () => {
    if (!passphrase) {
      onError('Passphrase required to encrypt document');
      return;
    }

    if (recipients.length === 0) {
      onError('At least one recipient is required');
      return;
    }

    try {
      setIsSaving(true);

      const content = getDocumentContent();
      if (!content.trim()) {
        onError('Document content cannot be empty');
        return;
      }

      const createRequest: CreateDocumentRequest = {
        title: documentTitle,
        content,
        recipients,
        policy,
        passphrase,
      };

      const encryptedDoc = await invoke<{ file_path: string }>('create_document', createRequest);

      // Ask user where to save the file
      const savePath = await save({
        defaultPath: `${documentTitle}.securedoc`,
        filters: [{
          name: 'Secure Document',
          extensions: ['securedoc']
        }]
      });

      if (savePath) {
        await invoke('save_document_to_path', {
          sourcePath: encryptedDoc.file_path,
          targetPath: savePath,
        });

        // Clear sensitive data
        setPassphrase('');
        setShowSaveDialog(false);

        onError(''); // Clear any existing errors
        // Could show success message here
      }

    } catch (error) {
      onError(`Failed to save document: ${error}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleNewDocument = () => {
    if (editorView) {
      const state = EditorState.create({
        schema: mySchema,
        plugins: exampleSetup({ schema: mySchema }),
      });
      editorView.updateState(state);
    }
    setDocumentTitle('Untitled Document');
    setRecipients([]);
    setPassphrase('');
    setShowSaveDialog(false);
  };

  return (
    <div className="document-editor">
      <div className="editor-toolbar">
        <div className="document-info">
          <input
            type="text"
            value={documentTitle}
            onChange={(e) => setDocumentTitle(e.target.value)}
            className="document-title"
            placeholder="Document title..."
          />
          <span className="author-info">
            Author: {identity.fingerprint.slice(0, 8)}...
          </span>
        </div>

        <div className="editor-actions">
          <button onClick={handleNewDocument} className="new-doc-button">
            New Document
          </button>
          <button
            onClick={() => setShowSaveDialog(true)}
            className="save-button primary"
            disabled={isSaving}
          >
            {isSaving ? 'Encrypting...' : 'Save Encrypted'}
          </button>
        </div>
      </div>

      <div className="editor-container">
        <div ref={editorRef} className="prosemirror-editor" />
      </div>

      {showSaveDialog && (
        <div className="save-dialog-overlay">
          <div className="save-dialog">
            <h3>Encrypt & Save Document</h3>

            <div className="form-group">
              <label>Recipients (Public Keys or Fingerprints)</label>
              <div className="recipients-input">
                <input
                  type="text"
                  value={newRecipient}
                  onChange={(e) => setNewRecipient(e.target.value)}
                  placeholder="Enter recipient fingerprint..."
                  onKeyPress={(e) => e.key === 'Enter' && addRecipient()}
                />
                <button onClick={addRecipient} type="button">Add</button>
              </div>
              <div className="recipients-list">
                {recipients.map((recipient) => (
                  <span key={recipient} className="recipient-tag">
                    {recipient.slice(0, 12)}...
                    <button onClick={() => removeRecipient(recipient)}>×</button>
                  </span>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label>Document Policy</label>
              <div className="policy-options">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={policy.require_hardware_token}
                    onChange={(e) => setPolicy({
                      ...policy,
                      require_hardware_token: e.target.checked
                    })}
                  />
                  Require Hardware Token
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={policy.watermark_enabled}
                    onChange={(e) => setPolicy({
                      ...policy,
                      watermark_enabled: e.target.checked
                    })}
                  />
                  Enable Watermark
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={!policy.offline_open_allowed}
                    onChange={(e) => setPolicy({
                      ...policy,
                      offline_open_allowed: !e.target.checked
                    })}
                  />
                  Require Online Verification
                </label>
              </div>
            </div>

            <div className="form-group">
              <label>Encryption Passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter encryption passphrase..."
                className="passphrase-input"
              />
            </div>

            <div className="dialog-actions">
              <button
                onClick={() => setShowSaveDialog(false)}
                className="cancel-button"
                disabled={isSaving}
              >
                Cancel
              </button>
              <button
                onClick={handleSaveDocument}
                className="save-button primary"
                disabled={isSaving || !passphrase || recipients.length === 0}
              >
                {isSaving ? 'Encrypting...' : 'Encrypt & Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DocumentEditor;