import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  createContext,
  useContext,
} from "react";
import {
  deriveKey,
  encrypt,
  decrypt,
  EncryptedData as CipherContent,
} from "../lib/encryption";
import { generatePassword, PasswordOptions } from "../lib/passwordGenerator";
import {
  ArrowPathIcon,
  EyeIcon,
  EyeSlashIcon,
  ClipboardIcon,
  TrashIcon,
  PencilIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  KeyIcon,
  LockClosedIcon,
  PlusIcon,
  CheckCircleIcon,
  SunIcon,
  MoonIcon,
} from "@heroicons/react/24/outline";

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface VaultItem {
  _id?: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
}

interface EncryptedVaultItem {
  _id: string;
  encryptedData: string;
  searchableKeywords: string[];
}

interface AuthState {
  token: string | null;
  userId: string | null;
  masterKey: CryptoJS.lib.WordArray | null;
  isAuthenticated: boolean;
  ENCRYPTION_SALT: string | null;
}

interface AuthFormData {
  email: string;
  masterPassword: string;
  isLogin: boolean;
}

interface AuthPanelProps {
  authForm: AuthFormData;
  setAuthForm: React.Dispatch<React.SetStateAction<AuthFormData>>;
  handleAuthSubmit: (e: React.FormEvent) => Promise<void>;
  loading: boolean;
  error: string | null;
}

interface VaultListProps {
  items: VaultItem[];
  onEdit: (item: VaultItem) => void;
  onDelete: (id: string) => void;
  loading: boolean;
}

interface VaultItemCardProps {
  item: VaultItem;
  onEdit: (item: VaultItem) => void;
  onDelete: (id: string) => void;
}

interface VaultFormProps {
  item: VaultItem | null;
  onSave: (item: VaultItem) => void;
  onClose: () => void;
  loading: boolean;
}

// ============================================================================
// CONSTANTS
// ============================================================================

const API_BASE = "/api";
const CLIPBOARD_CLEAR_DELAY = 15000; // 15 seconds
const MESSAGE_DISPLAY_DURATION = 1000; // 1 second
const MAX_DISPLAY_ID_LENGTH = 8;

const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 16,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: false,
  excludeLookAlikes: true,
};

const INITIAL_AUTH_STATE: AuthState = {
  token: null,
  userId: null,
  masterKey: null,
  isAuthenticated: false,
  ENCRYPTION_SALT: null,
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const extractSearchableKeywords = (item: VaultItem): string[] => {
  return [item.title, item.username, item.url]
    .join(" ")
    .toLowerCase()
    .split(/\s+/)
    .filter((keyword) => keyword.length > 1);
};

const copyToClipboard = async (
  text: string,
  onSuccess: () => void,
  onError: (error: Error) => void
): Promise<void> => {
  if (!navigator.clipboard) {
    onError(new Error("Clipboard API not available"));
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    onSuccess();

    // Auto-clear clipboard after delay
    setTimeout(async () => {
      await navigator.clipboard.writeText("");
    }, CLIPBOARD_CLEAR_DELAY);
  } catch (err) {
    onError(err as Error);
  }
};

const truncateText = (text: string, maxLength: number): string => {
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================

const PasswordVaultApp: React.FC = () => {
  // Authentication state
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);
  const [authForm, setAuthForm] = useState<AuthFormData>({
    email: "",
    masterPassword: "",
    isLogin: true,
  });

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [isFormVisible, setIsFormVisible] = useState(false);

  // Data state
  const [vaultItems, setVaultItems] = useState<EncryptedVaultItem[]>([]);
  const [decryptedVault, setDecryptedVault] = useState<VaultItem[]>([]);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);

  // ============================================================================
  // AUTHENTICATION HANDLERS
  // ============================================================================

  const handleAuthSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const endpoint = authForm.isLogin
      ? `${API_BASE}/auth/login`
      : `${API_BASE}/auth/signup`;

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: authForm.email,
          masterPassword: authForm.masterPassword,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(
          data.message ||
            `${authForm.isLogin ? "Login" : "Signup"} failed. Please try again.`
        );
        return;
      }

      if (authForm.isLogin) {
        const masterKey = deriveKey(authForm.masterPassword);

        setAuth({
          token: data.token,
          userId: data.userId,
          masterKey,
          isAuthenticated: true,
          ENCRYPTION_SALT: data.ENCRYPTION_SALT,
        });

        // Clear master password from form
        setAuthForm((prev) => ({ ...prev, masterPassword: "" }));
      } else {
        alert("Account created successfully. Please log in.");
        setAuthForm((prev) => ({ ...prev, isLogin: true, masterPassword: "" }));
      }
    } catch (err) {
      setError("Network error. Please check your connection and try again.");
      console.error("Authentication error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = (): void => {
    setAuth(INITIAL_AUTH_STATE);
    setVaultItems([]);
    setDecryptedVault([]);
    setSearchTerm("");
    setIsFormVisible(false);
    setEditingItem(null);
  };

  // ============================================================================
  // VAULT ITEM OPERATIONS
  // ============================================================================

  const decryptVaultItems = useCallback(
    (
      items: EncryptedVaultItem[],
      key: CryptoJS.lib.WordArray | null
    ): VaultItem[] => {
      if (!key) return [];

      return items.map((item) => {
        try {
          const decryptedJson = decrypt(item.encryptedData, key);

          if (!decryptedJson) {
            throw new Error("Decryption returned null");
          }

          const decryptedItem: VaultItem = JSON.parse(decryptedJson);
          return { ...decryptedItem, _id: item._id };
        } catch (error) {
          console.error("Decryption error for item:", item._id, error);

          return {
            _id: item._id,
            title: "⚠️ Decryption Failed",
            username: "N/A",
            password: "N/A",
            url: "N/A",
            notes:
              "Unable to decrypt. Check your master password or data integrity.",
          } as VaultItem;
        }
      });
    },
    []
  );

  const fetchVaultItems = useCallback(async (): Promise<void> => {
    if (!auth.isAuthenticated || !auth.token) return;

    try {
      const response = await fetch(`${API_BASE}/vault`, {
        headers: { Authorization: `Bearer ${auth.token}` },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch vault items");
      }

      const data = await response.json();
      setVaultItems(data.data || []);
    } catch (err) {
      console.error("Fetch vault error:", err);
      setError("Unable to load vault data. Please try again.");
    }
  }, [auth.isAuthenticated, auth.token]);

  const saveVaultItem = async (item: VaultItem): Promise<void> => {
    if (!auth.token || !auth.masterKey) return;

    setLoading(true);
    setError(null);

    try {
      const plaintext = JSON.stringify(item);
      const encryptedData = encrypt(plaintext, auth.masterKey);
      const searchableKeywords = extractSearchableKeywords(item);

      const isUpdate = !!item._id;
      const method = isUpdate ? "PUT" : "POST";
      const body = isUpdate
        ? {
            _id: item._id,
            updatedEncryptedData: encryptedData,
            updatedSearchableKeywords: searchableKeywords,
          }
        : { encryptedData, searchableKeywords };

      const response = await fetch(`${API_BASE}/vault`, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth.token}`,
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        throw new Error(
          `Failed to ${isUpdate ? "update" : "create"} vault item`
        );
      }

      await fetchVaultItems();
      setIsFormVisible(false);
      setEditingItem(null);
    } catch (err) {
      console.error("Save vault item error:", err);
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const deleteVaultItem = async (id: string): Promise<void> => {
    if (!auth.token) return;

    const confirmed = window.confirm(
      "Are you sure you want to delete this entry? This action cannot be undone."
    );

    if (!confirmed) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/vault?id=${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${auth.token}` },
      });

      if (!response.ok) {
        throw new Error("Failed to delete vault item");
      }

      await fetchVaultItems();
    } catch (err) {
      console.error("Delete vault item error:", err);
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const startEdit = (item: VaultItem): void => {
    setEditingItem(item);
    setIsFormVisible(true);
  };

  // ============================================================================
  // EFFECTS
  // ============================================================================

  useEffect(() => {
    if (auth.isAuthenticated) {
      fetchVaultItems();
    }
  }, [auth.isAuthenticated, fetchVaultItems]);

  useEffect(() => {
    if (auth.masterKey && vaultItems.length > 0) {
      const decrypted = decryptVaultItems(vaultItems, auth.masterKey);
      setDecryptedVault(decrypted);
    } else {
      setDecryptedVault([]);
    }
  }, [vaultItems, auth.masterKey, decryptVaultItems]);

  // ============================================================================
  // COMPUTED VALUES
  // ============================================================================

  const filteredVault = useMemo(() => {
    if (!searchTerm.trim()) return decryptedVault;

    const lowerSearch = searchTerm.toLowerCase();

    return decryptedVault.filter(
      (item) =>
        item.title?.toLowerCase().includes(lowerSearch) ||
        item.username?.toLowerCase().includes(lowerSearch) ||
        item.url?.toLowerCase().includes(lowerSearch) ||
        item.notes?.toLowerCase().includes(lowerSearch)
    );
  }, [decryptedVault, searchTerm]);

  // ============================================================================
  // RENDER
  // ============================================================================

  if (!auth.isAuthenticated) {
    return (
      <AuthPanel
        authForm={authForm}
        setAuthForm={setAuthForm}
        handleAuthSubmit={handleAuthSubmit}
        loading={loading}
        error={error}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header */}
        <header className="bg-white shadow-sm rounded-2xl px-6 py-4 mb-6">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-indigo-100 rounded-xl">
                <LockClosedIcon className="w-6 h-6 text-indigo-600" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">
                  Password Vault
                </h1>
                <p className="text-sm text-gray-500">
                  Secured with end-to-end encryption
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-xs text-gray-500">User ID</p>
                <p className="text-sm font-mono text-gray-700">
                  {truncateText(auth.userId || "", MAX_DISPLAY_ID_LENGTH)}
                </p>
              </div>
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-red-50 text-red-600 text-sm font-medium rounded-lg hover:bg-red-100 transition-colors duration-200"
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        {/* Error Banner */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl mb-6 flex items-start">
            <div className="flex-1">
              <p className="font-medium">Error</p>
              <p className="text-sm">{error}</p>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-red-500 hover:text-red-700"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Password Generator Section */}
        <section className="bg-white shadow-sm rounded-2xl p-6 mb-6">
          <div className="flex items-center space-x-3 mb-4">
            <KeyIcon className="w-5 h-5 text-indigo-600" />
            <h2 className="text-xl font-semibold text-gray-900">
              Password Generator
            </h2>
          </div>
          <PasswordGenerator />
        </section>

        {/* Vault Section */}
        <section className="bg-white shadow-sm rounded-2xl p-6">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-6">
            <h2 className="text-xl font-semibold text-gray-900">
              My Vault
              <span className="ml-2 text-sm font-normal text-gray-500">
                ({filteredVault.length}{" "}
                {filteredVault.length === 1 ? "item" : "items"})
              </span>
            </h2>

            <div className="flex flex-col sm:flex-row gap-3">
              {/* Search Input */}
              <div className="relative">
                <MagnifyingGlassIcon className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search vault..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-10 py-2 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent w-full sm:w-80 transition-all duration-200"
                />
                {searchTerm && (
                  <button
                    onClick={() => setSearchTerm("")}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    <XMarkIcon className="w-5 h-5" />
                  </button>
                )}
              </div>

              {/* Add New Button */}
              <button
                onClick={() => {
                  setIsFormVisible(true);
                  setEditingItem(null);
                }}
                className="px-5 py-2 bg-indigo-600 text-white font-medium rounded-xl hover:bg-indigo-700 transition-colors duration-200 flex items-center justify-center space-x-2 shadow-sm"
              >
                <PlusIcon className="w-5 h-5" />
                <span>New Entry</span>
              </button>
            </div>
          </div>

          <VaultList
            items={filteredVault}
            onEdit={startEdit}
            onDelete={deleteVaultItem}
            loading={loading}
          />
        </section>
      </div>

      {/* Vault Form Modal */}
      {isFormVisible && (
        <VaultForm
          item={editingItem}
          onSave={saveVaultItem}
          onClose={() => {
            setIsFormVisible(false);
            setEditingItem(null);
          }}
          loading={loading}
        />
      )}
    </div>
  );
};

// ============================================================================
// AUTH PANEL COMPONENT
// ============================================================================

const AuthPanel: React.FC<AuthPanelProps> = ({
  authForm,
  setAuthForm,
  handleAuthSubmit,
  loading,
  error,
}) => (
  <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-indigo-50 via-white to-purple-50 p-4">
    <div className="w-full max-w-md">
      <div className="bg-white p-8 rounded-2xl shadow-xl">
        {/* Logo & Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-2xl mb-4">
            <LockClosedIcon className="w-8 h-8 text-indigo-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Password Vault
          </h1>
          <p className="text-gray-600">
            Secure your passwords with client-side encryption
          </p>
        </div>

        {/* Auth Form */}
        <form onSubmit={handleAuthSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Email Address
            </label>
            <input
              id="email"
              type="email"
              placeholder="you@example.com"
              value={authForm.email}
              onChange={(e) =>
                setAuthForm({ ...authForm, email: e.target.value })
              }
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
              required
              autoComplete="email"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              placeholder="Enter your master password"
              value={authForm.masterPassword}
              onChange={(e) =>
                setAuthForm({ ...authForm, masterPassword: e.target.value })
              }
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
              required
              autoComplete={
                authForm.isLogin ? "current-password" : "new-password"
              }
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl">
              <p className="text-sm text-red-600">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full px-4 py-3 bg-indigo-600 text-white font-semibold rounded-xl shadow-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {loading ? (
              <>
                <svg
                  className="animate-spin h-5 w-5 mr-2"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Processing...
              </>
            ) : authForm.isLogin ? (
              "Sign In"
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        {/* Toggle Auth Mode */}
        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            {authForm.isLogin
              ? "Don't have an account?"
              : "Already have an account?"}
            <button
              onClick={() =>
                setAuthForm({
                  ...authForm,
                  isLogin: !authForm.isLogin,
                  masterPassword: "",
                })
              }
              className="ml-2 text-indigo-600 font-semibold hover:text-indigo-500 transition-colors duration-200"
              disabled={loading}
            >
              {authForm.isLogin ? "Sign Up" : "Sign In"}
            </button>
          </p>
        </div>
      </div>

      {/* Security Notice */}
      <div className="mt-6 text-center text-sm text-gray-500">
        <p>🔒 All encryption happens locally in your browser</p>
      </div>
    </div>
  </div>
);

// ============================================================================
// PASSWORD GENERATOR COMPONENT
// ============================================================================

const PasswordGenerator: React.FC = () => {
  const [options, setOptions] = useState<PasswordOptions>(
    DEFAULT_PASSWORD_OPTIONS
  );
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const generateAndSet = useCallback(() => {
    const newPassword = generatePassword(options);
    setPassword(newPassword);
  }, [options]);

  useEffect(() => {
    generateAndSet();
  }, [generateAndSet]);

  const handleOptionChange = (
    key: keyof PasswordOptions,
    value: string | boolean | number
  ): void => {
    setOptions((prev) => ({ ...prev, [key]: value }));
  };

  const handleCopy = (): void => {
    copyToClipboard(
      password,
      () => {
        setMessage("✓ Copied (auto-clears in 15s)");
        setTimeout(() => setMessage(""), MESSAGE_DISPLAY_DURATION);
      },
      (err) => {
        console.error("Copy failed:", err);
        setMessage("✗ Failed to copy");
        setTimeout(() => setMessage(""), MESSAGE_DISPLAY_DURATION);
      }
    );
  };

  return (
    <div className="space-y-4">
      {/* Password Display */}
      <div className="flex items-center bg-gray-50 rounded-xl p-4 border-2 border-gray-200">
        <input
          type="text"
          readOnly
          value={password}
          placeholder="Generated password will appear here"
          className="flex-grow bg-transparent text-lg font-mono text-gray-900 border-none focus:ring-0 p-0 outline-none"
        />
        <div className="flex items-center space-x-2 ml-3">
          <button
            onClick={handleCopy}
            className="p-2.5 bg-indigo-100 text-indigo-700 rounded-lg hover:bg-indigo-200 transition-colors duration-200"
            title="Copy to Clipboard"
          >
            <ClipboardIcon className="w-5 h-5" />
          </button>
          <button
            onClick={generateAndSet}
            className="p-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors duration-200"
            title="Generate New Password"
          >
            <ArrowPathIcon className="w-5 h-5" />
          </button>
        </div>
      </div>

      {message && (
        <div className="flex items-center space-x-2 text-sm text-green-600">
          <CheckCircleIcon className="w-4 h-4" />
          <span>{message}</span>
        </div>
      )}

      {/* Options */}
      <div className="space-y-4">
        {/* Length Slider */}
        <div>
          <div className="flex justify-between items-center mb-2">
            <label className=" font-medium text-gray-700 text-xl">
              Password Length
            </label>
            <span className="text-xl font-semibold text-indigo-600">
              {options.length} characters
            </span>
          </div>
          <input
            type="range"
            min="8"
            max="64"
            value={options.length}
            onChange={(e) =>
              handleOptionChange("length", parseInt(e.target.value, 10))
            }
            className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600 "
          />
          <div className="flex justify-between  text-gray-500 mt-1 text-sm">
            <span>8</span>
            <span>64</span>
          </div>
        </div>

        {/* Checkboxes */}
        <div className="grid grid-cols-1 sm:grid-cols-2   gap-3">
          {[
            { key: "includeUppercase", label: "Uppercase (A-Z)" },
            { key: "includeLowercase", label: "Lowercase (a-z)" },
            { key: "includeNumbers", label: "Numbers (0-9)" },
            { key: "includeSymbols", label: "Symbols (!@#$%)" },
            { key: "excludeLookAlikes", label: "Exclude Ambiguous (lIO01)" },
          ].map(({ key, label }) => (
            <label
              key={key}
              className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors duration-200 cursor-pointer"
            >
              <input
                id={key}
                type="checkbox"
                checked={options[key as keyof PasswordOptions] as boolean}
                onChange={(e) =>
                  handleOptionChange(
                    key as keyof PasswordOptions,
                    e.target.checked
                  )
                }
                className="w-4 h-4 text-indigo-600 bg-gray-100 border-gray-300 rounded focus:ring-indigo-500 focus:ring-2"
              />
              <span className="text-sm text-gray-700">{label}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// VAULT LIST COMPONENT
// ============================================================================

const VaultList: React.FC<VaultListProps> = ({
  items,
  onEdit,
  onDelete,
  loading,
}) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <svg
          className="animate-spin h-10 w-10 text-indigo-600 mb-4"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
        <p className="text-gray-500">Loading your vault...</p>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="text-center py-16">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-gray-100 rounded-full mb-4">
          <LockClosedIcon className="w-8 h-8 text-gray-400" />
        </div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">
          Your vault is empty
        </h3>
        <p className="text-gray-500 mb-6">
          Get started by adding your first password entry
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((item) => (
        <VaultItemCard
          key={item._id}
          item={item}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      ))}
    </div>
  );
};

// ============================================================================
// VAULT ITEM CARD COMPONENT
// ============================================================================

const VaultItemCard: React.FC<VaultItemCardProps> = ({
  item,
  onEdit,
  onDelete,
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [copyMessage, setCopyMessage] = useState("");

  const handleCopyPassword = (): void => {
    copyToClipboard(
      item.password,
      () => {
        setCopyMessage("Copied!");
        setTimeout(() => setCopyMessage(""), MESSAGE_DISPLAY_DURATION);
      },
      (err) => {
        console.error("Copy failed:", err);
        setCopyMessage("Failed");
        setTimeout(() => setCopyMessage(""), MESSAGE_DISPLAY_DURATION);
      }
    );
  };

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5 hover:shadow-md hover:border-indigo-200 transition-all duration-200">
      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <div className="flex-1 min-w-0 mr-4">
          <h3 className="text-lg font-semibold text-gray-900 truncate mb-1">
            {item.title}
          </h3>
          {item.url && (
            <a
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-indigo-600 hover:text-indigo-700 hover:underline truncate block"
            >
              {item.url}
            </a>
          )}
        </div>

        <div className="flex items-center space-x-1">
          <button
            onClick={() => onEdit(item)}
            className="p-2 text-gray-600 hover:bg-indigo-50 hover:text-indigo-600 rounded-lg transition-colors duration-200"
            title="Edit Entry"
          >
            <PencilIcon className="w-5 h-5" />
          </button>
          <button
            onClick={() => onDelete(item._id!)}
            className="p-2 text-gray-600 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors duration-200"
            title="Delete Entry"
          >
            <TrashIcon className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Username */}
        <div>
          <label className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1 block">
            Username
          </label>
          <p className="text-sm text-gray-900 truncate font-medium">
            {item.username || "—"}
          </p>
        </div>

        {/* Password */}
        <div>
          <label className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1 block">
            Password
          </label>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-sm text-gray-900 flex-1 truncate">
              {showPassword ? item.password : "••••••••••••"}
            </span>
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="p-1.5 text-gray-500 hover:bg-gray-100 rounded-md transition-colors duration-200"
                title={showPassword ? "Hide Password" : "Show Password"}
              >
                {showPassword ? (
                  <EyeSlashIcon className="w-4 h-4" />
                ) : (
                  <EyeIcon className="w-4 h-4" />
                )}
              </button>
              <button
                onClick={handleCopyPassword}
                className="p-1.5 text-indigo-600 hover:bg-indigo-50 rounded-md transition-colors duration-200 relative"
                title="Copy Password"
              >
                <ClipboardIcon className="w-4 h-4" />
                {copyMessage && (
                  <span className="absolute -top-8 left-1/2 transform -translate-x-1/2 text-xs bg-gray-900 text-white px-2 py-1 rounded whitespace-nowrap">
                    {copyMessage}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Notes */}
      {item.notes && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <label className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2 block">
            Notes
          </label>
          <p className="text-sm text-gray-700 whitespace-pre-wrap break-words">
            {item.notes}
          </p>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// VAULT FORM COMPONENT
// ============================================================================

const VaultForm: React.FC<VaultFormProps> = ({
  item,
  onSave,
  onClose,
  loading,
}) => {
  const [formData, setFormData] = useState<VaultItem>(
    item || {
      title: "",
      username: "",
      password: "",
      url: "",
      notes: "",
    }
  );

  const [passwordGenOptions, setPasswordGenOptions] = useState<PasswordOptions>(
    DEFAULT_PASSWORD_OPTIONS
  );

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ): void => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleGeneratePassword = (): void => {
    const newPassword = generatePassword(passwordGenOptions);
    setFormData((prev) => ({ ...prev, password: newPassword }));
  };

  const handleSubmit = (e: React.FormEvent): void => {
    e.preventDefault();
    onSave(formData);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center rounded-t-2xl">
          <h3 className="text-xl font-bold text-gray-900">
            {item ? "Edit Entry" : "New Entry"}
          </h3>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors duration-200"
            disabled={loading}
          >
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Title */}
          <div>
            <label
              htmlFor="title"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Title <span className="text-red-500">*</span>
            </label>
            <input
              id="title"
              type="text"
              name="title"
              placeholder="e.g., Google Account, Bank Login"
              value={formData.title}
              onChange={handleChange}
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
              required
            />
          </div>

          {/* Username */}
          <div>
            <label
              htmlFor="username"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Username / Email <span className="text-red-500">*</span>
            </label>
            <input
              id="username"
              type="text"
              name="username"
              placeholder="your.email@example.com"
              value={formData.username}
              onChange={handleChange}
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
              required
              autoComplete="username"
            />
          </div>

          {/* Password */}
          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Password <span className="text-red-500">*</span>
            </label>
            <div className="flex items-center space-x-2">
              <input
                id="password"
                type="text"
                name="password"
                placeholder="Enter or generate a password"
                value={formData.password}
                onChange={handleChange}
                className="flex-1 px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono transition-all duration-200"
                required
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={handleGeneratePassword}
                className="p-3 bg-indigo-100 text-indigo-600 rounded-xl hover:bg-indigo-200 transition-colors duration-200 flex-shrink-0"
                title="Generate Password"
              >
                <KeyIcon className="w-6 h-6" />
              </button>
            </div>
          </div>

          {/* Password Generator Options */}
          <div className="bg-gray-50 rounded-xl p-4 space-y-3">
            <p className="text-sm font-medium text-gray-700">
              Password Generator Options
            </p>
            <div className="flex flex-wrap gap-4 text-sm">
              <div className="flex items-center space-x-2">
                <label className="text-gray-600">Length:</label>
                <input
                  type="range"
                  min="8"
                  max="32"
                  value={passwordGenOptions.length}
                  onChange={(e) =>
                    setPasswordGenOptions((p) => ({
                      ...p,
                      length: parseInt(e.target.value, 10),
                    }))
                  }
                  className="w-24 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                />
                <span className="font-semibold text-indigo-600 w-8">
                  {passwordGenOptions.length}
                </span>
              </div>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={passwordGenOptions.includeSymbols}
                  onChange={(e) =>
                    setPasswordGenOptions((p) => ({
                      ...p,
                      includeSymbols: e.target.checked,
                    }))
                  }
                  className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500"
                />
                <span className="text-gray-700">Symbols</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={passwordGenOptions.includeNumbers}
                  onChange={(e) =>
                    setPasswordGenOptions((p) => ({
                      ...p,
                      includeNumbers: e.target.checked,
                    }))
                  }
                  className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500"
                />
                <span className="text-gray-700">Numbers</span>
              </label>
            </div>
          </div>

          {/* URL */}
          <div>
            <label
              htmlFor="url"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Website URL
            </label>
            <input
              id="url"
              type="url"
              name="url"
              placeholder="https://example.com"
              value={formData.url}
              onChange={handleChange}
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
            />
          </div>

          {/* Notes */}
          <div>
            <label
              htmlFor="notes"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Notes
            </label>
            <textarea
              id="notes"
              name="notes"
              placeholder="Add any additional information..."
              value={formData.notes}
              onChange={handleChange}
              rows={4}
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none transition-all duration-200"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
            <button
              type="button"
              onClick={onClose}
              className="px-6 py-2.5 bg-gray-100 text-gray-700 font-medium rounded-xl hover:bg-gray-200 transition-colors duration-200"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 bg-indigo-600 text-white font-medium rounded-xl shadow-sm hover:bg-indigo-700 transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
            >
              {loading ? (
                <>
                  <svg
                    className="animate-spin h-5 w-5 mr-2"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                  Saving...
                </>
              ) : item ? (
                "Update Entry"
              ) : (
                "Save Entry"
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default PasswordVaultApp;
