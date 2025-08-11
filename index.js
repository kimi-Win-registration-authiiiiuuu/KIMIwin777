// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyD0Ne46PQqmvUnsq89GUJlKfLpWvsHmtbk",
  authDomain: "kimi-win-90b82.firebaseapp.com",
  databaseURL: "https://kimi-win-90b82-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "kimi-win-90b82",
  storageBucket: "kimi-win-90b82.appspot.com",
  messagingSenderId: "889222798634",
  appId: "1:889222798634:web:86770b996003152f19d253"
};

const REDIRECT_URL = "go:home";

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const database = firebase.database();

// User-friendly error messages
const errorMessages = {
  "auth/invalid-email": "Please enter a valid email address",
  "auth/user-disabled": "This account has been disabled",
  "auth/user-not-found": "No account found with this email",
  "auth/wrong-password": "Incorrect password",
  "auth/email-already-in-use": "This email is already registered",
  "auth/operation-not-allowed": "This operation is not allowed",
  "auth/weak-password": "Password is too weak (min 8 characters)",
  "auth/too-many-requests": "Too many attempts. Please try again later",
  "auth/network-request-failed": "Network error. Please check your connection",
  "auth/expired-action-code": "The action code has expired. Please try again",
  "auth/invalid-action-code": "Invalid action code. Please try again",
  "default": "please enter a valid email address/password.or Please try again later"
};

// Current user waiting for verification
let unverifiedUser = null;
let currentMode = 'default'; // default, resetPassword, verifyEmail, referral

// Check URL parameters on page load
window.onload = function() {
  const urlParams = new URLSearchParams(window.location.search);
  
  // Check for password reset mode
  if (urlParams.has('mode') && urlParams.get('mode') === 'resetPassword') {
    showPasswordResetForm();
    return;
  }
  
  // Check for email verification mode
  if (urlParams.has('mode') && urlParams.get('mode') === 'verifyEmail') {
    handleEmailVerification();
    return;
  }
  
  // Check for referral mode
  if (urlParams.has('ref')) {
    showDownloadAppForm(urlParams.get('ref'));
    return;
  }
  
  // Default auth page
  showDefaultAuth();
};

// Show default authentication page
function showDefaultAuth() {
  currentMode = 'default';
  document.getElementById('authTabs').style.display = 'flex';
  document.getElementById('passwordResetForm').classList.remove('active');
  document.getElementById('downloadAppForm').classList.remove('active');
  document.getElementById('verificationSuccess').style.display = 'none';
  document.getElementById('downloadSuccess').style.display = 'none';
  
  document.getElementById('pageTitle').textContent = 'Welcome Back!';
  document.getElementById('pageSubtitle').textContent = 'Please Sign in to access your account';
  
  showTab('login');
}

// Show password reset form
function showPasswordResetForm() {
  currentMode = 'resetPassword';
  document.getElementById('authTabs').style.display = 'none';
  document.getElementById('login').classList.remove('active');
  document.getElementById('signup').classList.remove('active');
  document.getElementById('passwordResetForm').classList.add('active');
  document.getElementById('downloadAppForm').classList.remove('active');
  document.getElementById('verificationSuccess').style.display = 'none';
  document.getElementById('downloadSuccess').style.display = 'none';
  
  document.getElementById('pageTitle').textContent = 'Reset Your Password';
  document.getElementById('pageSubtitle').textContent = 'Create a new password for your account';
}

// Show download app/referral form
function showDownloadAppForm(referralCode = '') {
  currentMode = 'referral';
  document.getElementById('authTabs').style.display = 'none';
  document.getElementById('login').classList.remove('active');
  document.getElementById('signup').classList.remove('active');
  document.getElementById('passwordResetForm').classList.remove('active');
  document.getElementById('downloadAppForm').classList.add('active');
  document.getElementById('verificationSuccess').style.display = 'none';
  document.getElementById('downloadSuccess').style.display = 'none';
  
  document.getElementById('pageTitle').textContent = 'Join Kimi-Win Today!';
  document.getElementById('pageSubtitle').textContent = 'Register to start your earning journey';
  
  // Set referral code if provided in URL
  if (referralCode) {
    document.getElementById('referralCode').value = referralCode.toUpperCase();
  }
}

// Handle email verification from URL
function handleEmailVerification() {
  const urlParams = new URLSearchParams(window.location.search);
  const oobCode = urlParams.get('oobCode');
  
  if (!oobCode) {
    showToast("Invalid verification link", "error");
    showDefaultAuth();
    return;
  }
  
  // Apply the verification code
  auth.applyActionCode(oobCode)
    .then(() => {
      // Email verified successfully
      document.getElementById('authTabs').style.display = 'none';
      document.getElementById('login').classList.remove('active');
      document.getElementById('signup').classList.remove('active');
      document.getElementById('passwordResetForm').classList.remove('active');
      document.getElementById('downloadAppForm').classList.remove('active');
      document.getElementById('verificationSuccess').style.display = 'block';
      document.getElementById('downloadSuccess').style.display = 'none';
      
      document.getElementById('pageTitle').textContent = 'Email Verified!';
      document.getElementById('pageSubtitle').textContent = 'Your email has been successfully verified';
    })
    .catch(error => {
      showToast(getErrorMessage(error), 'error');
      showDefaultAuth();
    });
}

// Show verification modal
function showVerificationModal(email) {
  document.getElementById('verificationMessage').textContent = 
    `A verification link has been sent to ${email}. Please check your inbox and click the link to verify your account before proceeding.`;
  document.getElementById('verificationModal').classList.add('active');
}

// Hide verification modal
function hideVerificationModal() {
  document.getElementById('verificationModal').classList.remove('active');
}

// Resend verification email
function resendVerificationEmail() {
  if (unverifiedUser) {
    unverifiedUser.sendEmailVerification()
      .then(() => {
        showToast("Verification email resent successfully!", 'success');
      })
      .catch(error => {
        showToast(getErrorMessage(error), 'error');
      });
  }
}

// Check if email is verified
function checkEmailVerification() {
  if (unverifiedUser) {
    unverifiedUser.reload()
      .then(() => {
        if (unverifiedUser.emailVerified) {
          hideVerificationModal();
          showToast("Email verified successfully!", 'success');
          processVerifiedUser(unverifiedUser);
        } else {
          showToast("Email not verified yet. Please check your inbox.", 'warning');
        }
      })
      .catch(error => {
        showToast(getErrorMessage(error), 'error');
      });
  }
}

// Process verified user
function processVerifiedUser(user) {
  saveToLocalStorage(user, "email/password");
  ensureUserExists(user)
    .then(() => {
      showToast(`Welcome ${user.email}!`, 'success');
      showReferralPopup(user.uid);
    })
    .catch(error => {
      showToast("Error setting up your account. Please try again.", 'error');
      console.error("Error ensuring user exists:", error);
    });
}

// Securely generate a random 10-character referral code
function generateReferralCode(length = 10) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const values = new Uint32Array(length);
  window.crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += charset[values[i] % charset.length];
  }
  return result;
}

// Generate unique referral code by checking existing ones
async function generateUniqueReferralCode(retries = 5) {
  for (let i = 0; i < retries; i++) {
    const code = generateReferralCode();
    const snapshot = await database.ref("referralCodes/" + code).once("value");
    if (!snapshot.exists()) {
      return code;
    }
  }
  throw new Error("Failed to generate unique referral code after multiple attempts.");
}

// Create user data in Realtime Database with unique referral code
async function createUserData(user) {
  const userId = user.uid;
  const email = user.email || "Guest Account";
  const referralCode = await generateUniqueReferralCode();
  const timestamp = firebase.database.ServerValue.TIMESTAMP;

  const userData = {
    email: email,
    referralCode: referralCode,
    BankDetails: {
      accountNumber: "",
      accountName: "",
      bankName: "",
      ifscCode: ""
    },
    totalBalance: 0,
    withdrawableBalance: 0,
    history: {},
    depositHistory: {},
    withdrawalHistory: {},
    Referrals: {},
    referralEarnings: 0,
    notifications: {},
    createdAt: timestamp,
    lastLogin: timestamp,
    hasUsedReferral: false,
    emailVerified: user.emailVerified || false
  };

  // Save user and referralCode reference
  await Promise.all([
    database.ref('appusers/' + userId).set(userData),
    database.ref('referralCodes/' + referralCode).set(userId)
  ]);

  console.log("User data created successfully with unique referral code");
  return userData;
}

// Update last login timestamp
function updateLastLogin(userId) {
  return database.ref('appusers/' + userId + '/lastLogin').set(firebase.database.ServerValue.TIMESTAMP);
}

// Check if user exists in database, if not create
function ensureUserExists(user) {
  return database.ref('appusers/' + user.uid).once('value')
    .then(snapshot => {
      if (!snapshot.exists()) {
        return createUserData(user);
      } else {
        return updateLastLogin(user.uid);
      }
    });
}

// Show toast notification
function showToast(message, type = 'success') {
  const toast = document.getElementById('toast');
  const toastMessage = document.getElementById('toast-message');
  const toastIcon = toast.querySelector('i');

  toast.className = `toast ${type}`;
  toastMessage.textContent = message;

  if (type === 'success') {
    toastIcon.className = 'fas fa-check-circle';
  } else if (type === 'error') {
    toastIcon.className = 'fas fa-exclamation-circle';
  } else if (type === 'warning') {
    toastIcon.className = 'fas fa-exclamation-triangle';
  }

  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}

// Get user-friendly error message
function getErrorMessage(error) {
  const code = error.code || error.message;
  return errorMessages[code] || errorMessages.default;
}

// Tab switching
function showTab(tabId) {
  document.querySelectorAll('.auth-form').forEach(form => {
    form.classList.remove('active');
  });
  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.classList.remove('active');
  });

  document.getElementById(tabId).classList.add('active');
  document.querySelector(`.auth-tab[onclick="showTab('${tabId}')"]`).classList.add('active');
}

// Save to localStorage
function saveToLocalStorage(user, method) {
  localStorage.setItem("uid", user.uid);
  localStorage.setItem("email", user.email || "Guest Account");
  localStorage.setItem("login_method", method);
}

// Check password strength
function checkPasswordStrength() {
  const password = document.getElementById('signupPassword').value;
  const strengthBar = document.getElementById('passwordStrength');
  
  // Reset
  strengthBar.style.width = '0%';
  strengthBar.style.backgroundColor = '#e74c3c';
  
  if (password.length === 0) return;
  
  // Check strength
  let strength = 0;
  
  // Length
  if (password.length >= 8) strength += 25;
  if (password.length >= 12) strength += 15;
  
  // Contains numbers
  if (/\d/.test(password)) strength += 20;
  
  // Contains lowercase
  if (/[a-z]/.test(password)) strength += 15;
  
  // Contains uppercase
  if (/[A-Z]/.test(password)) strength += 15;
  
  // Contains special chars
  if (/[^A-Za-z0-9]/.test(password)) strength += 10;
  
  // Update UI
  strength = Math.min(strength, 100);
  strengthBar.style.width = strength + '%';
  
  // Color based on strength
  if (strength < 40) {
    strengthBar.style.backgroundColor = '#e74c3c'; // Red
  } else if (strength < 70) {
    strengthBar.style.backgroundColor = '#f39c12'; // Orange
  } else {
    strengthBar.style.backgroundColor = '#2ecc71'; // Green
  }
}

// Check reset password strength
function checkResetPasswordStrength() {
  const password = document.getElementById('resetPassword').value;
  const strengthBar = document.getElementById('resetPasswordStrength');
  
  // Same logic as checkPasswordStrength but for reset password field
  strengthBar.style.width = '0%';
  strengthBar.style.backgroundColor = '#e74c3c';
  
  if (password.length === 0) return;
  
  let strength = 0;
  if (password.length >= 8) strength += 25;
  if (password.length >= 12) strength += 15;
  if (/\d/.test(password)) strength += 20;
  if (/[a-z]/.test(password)) strength += 15;
  if (/[A-Z]/.test(password)) strength += 15;
  if (/[^A-Za-z0-9]/.test(password)) strength += 10;
  
  strength = Math.min(strength, 100);
  strengthBar.style.width = strength + '%';
  
  if (strength < 40) {
    strengthBar.style.backgroundColor = '#e74c3c';
  } else if (strength < 70) {
    strengthBar.style.backgroundColor = '#f39c12';
  } else {
    strengthBar.style.backgroundColor = '#2ecc71';
  }
}

// Check download password strength
function checkDownloadPasswordStrength() {
  const password = document.getElementById('downloadPassword').value;
  const strengthBar = document.getElementById('downloadPasswordStrength');
  
  // Same logic as checkPasswordStrength but for download password field
  strengthBar.style.width = '0%';
  strengthBar.style.backgroundColor = '#e74c3c';
  
  if (password.length === 0) return;
  
  let strength = 0;
  if (password.length >= 8) strength += 25;
  if (password.length >= 12) strength += 15;
  if (/\d/.test(password)) strength += 20;
  if (/[a-z]/.test(password)) strength += 15;
  if (/[A-Z]/.test(password)) strength += 15;
  if (/[^A-Za-z0-9]/.test(password)) strength += 10;
  
  strength = Math.min(strength, 100);
  strengthBar.style.width = strength + '%';
  
  if (strength < 40) {
    strengthBar.style.backgroundColor = '#e74c3c';
  } else if (strength < 70) {
    strengthBar.style.backgroundColor = '#f39c12';
  } else {
    strengthBar.style.backgroundColor = '#2ecc71';
  }
}

// Validate email
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Validate password
function validatePassword(password) {
  // At least 8 characters, one uppercase, one lowercase, one number
  const re = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
  return re.test(password);
}

// Show password reset form
function showPasswordReset() {
  const email = document.getElementById('loginEmail').value;
  
  if (!validateEmail(email)) {
    showToast("Please enter a valid email address to reset password", 'error');
    return;
  }
  
  auth.sendPasswordResetEmail(email)
    .then(() => {
      showToast("Password reset link sent to your email", 'success');
    })
    .catch(error => {
      showToast(getErrorMessage(error), 'error');
    });
}

// Handle password reset from URL
function handlePasswordReset() {
  const password = document.getElementById('resetPassword').value;
  const confirmPassword = document.getElementById('resetConfirmPassword').value;
  
  if (!password || !confirmPassword) {
    showToast("Please fill in all fields", 'error');
    return;
  }
  
  if (!validatePassword(password)) {
    showToast("Password must be at least 8 characters with uppercase, lowercase and a number", 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showToast("Passwords don't match!", 'error');
    return;
  }
  
  // Show loading spinner
  document.getElementById('resetSpinner').style.display = 'block';
  
  const urlParams = new URLSearchParams(window.location.search);
  const oobCode = urlParams.get('oobCode');
  
  if (!oobCode) {
    showToast("Invalid password reset link", 'error');
    document.getElementById('resetSpinner').style.display = 'none';
    return;
  }
  
  // Verify the password reset code
  auth.verifyPasswordResetCode(oobCode)
    .then(email => {
      // Save email to localStorage for confirmation
      localStorage.setItem('emailForPasswordReset', email);
      
      // Confirm the password reset
      return auth.confirmPasswordReset(oobCode, password);
    })
    .then(() => {
      showToast("Password reset successfully!", 'success');
      document.getElementById('resetSpinner').style.display = 'none';
      
      // Show success message and redirect to login
      setTimeout(() => {
        window.location.href = window.location.pathname; // Remove query params
      }, 2000);
    })
    .catch(error => {
      document.getElementById('resetSpinner').style.display = 'none';
      showToast(getErrorMessage(error), 'error');
    });
}

// Show referral popup
function showReferralPopup(userId) {
  // Check if user has already used a referral code
  database.ref('appusers/' + userId + '/hasUsedReferral').once('value')
    .then(snapshot => {
      const hasUsedReferral = snapshot.val();
      
      if (!hasUsedReferral) {
        document.getElementById('referralPopup').classList.add('active');
      } else {
        // Redirect immediately if already used referral
        window.location.href = REDIRECT_URL;
      }
    })
    .catch(error => {
      console.error("Error checking referral status:", error);
      // Redirect if there's an error checking
      window.location.href = REDIRECT_URL;
    });
}

// Submit referral code
function submitReferralCode() {
  const referralCode = document.getElementById('referralCodeInput').value.trim();
  const userId = localStorage.getItem('uid');
  
  if (!referralCode) {
    skipReferralCode();
    return;
  }
  
  if (referralCode.length !== 10 || !/^[A-Z0-9]+$/.test(referralCode)) {
    showToast("Please enter a valid 10-digit referral code", 'error');
    return;
  }
  
  // Check if referral code exists
  database.ref('referralCodes/' + referralCode).once('value')
    .then(snapshot => {
      if (snapshot.exists()) {
        const refereeId = snapshot.val();
        
        if (refereeId === userId) {
          showToast("You cannot use your own referral code", 'error');
          return;
        }
        
// Process the referral
const timestamp = Date.now();
const updates = {};

updates[`appusers/${userId}/hasUsedReferral`] = true;
updates[`appusers/${userId}/referredVia`] = referralCode;
// Removed withdrawableBalance update for the new user
updates[`appusers/${userId}/totalBalance`] = firebase.database.ServerValue.increment(25);
updates[`appusers/${userId}/history/ref_used_${timestamp}`] = {
  type: 'referral_used',
  code: referralCode,
  amount: 25,
  timestamp: timestamp
};

// Add bonus to referee - removed withdrawableBalance increment
updates[`appusers/${refereeId}/referralEarnings`] = firebase.database.ServerValue.increment(25);
updates[`appusers/${refereeId}/totalBalance`] = firebase.database.ServerValue.increment(25);
updates[`appusers/${refereeId}/Referrals/${userId}`] = {
  email: localStorage.getItem('email') || "Guest Account",
  timestamp: timestamp,
  status: 'active',
  earned: 25
};
updates[`appusers/${refereeId}/history/ref_earned_${timestamp}`] = {
  type: 'referral_earned',
  from: userId,
  amount: 25,
  timestamp: timestamp
};

return database.ref().update(updates);
      } else {
        showToast("Invalid referral code", 'error');
        return Promise.reject("Invalid referral code");
      }
    })
    .then(() => {
      showToast("Referral code applied successfully! ₹25 added to your balance", 'success');
      document.getElementById('referralPopup').classList.remove('active');
      setTimeout(() => {
        window.location.href = REDIRECT_URL;
      }, 1500);
    })
    .catch(error => {
      console.error("Error processing referral:", error);
      showToast("Error processing referral code", 'error');
    });
}

// Skip referral code
function skipReferralCode() {
  const userId = localStorage.getItem('uid');
  
  // Mark as skipped
  database.ref('appusers/' + userId + '/hasUsedReferral').set(false)
    .then(() => {
      document.getElementById('referralPopup').classList.remove('active');
      window.location.href = REDIRECT_URL;
    })
    .catch(error => {
      console.error("Error skipping referral:", error);
      window.location.href = REDIRECT_URL;
    });
}

// Redirect after login
function redirectAfterLogin(user, method) {
  saveToLocalStorage(user, method);

  // Show loading spinner
  const spinnerId = method === 'email/password' ? 'loginSpinner' : 'signupSpinner';
  document.getElementById(spinnerId).style.display = 'block';
  
  ensureUserExists(user)
    .then(() => {
      showToast(`Welcome ${user.email || 'Dear Guest'}!`, 'success');
      
      // For email/password login, check verification status
      if (method === 'email/password') {
        if (user.emailVerified) {
          // Show referral popup for verified users
          showReferralPopup(user.uid);
        } else {
          // Show verification modal for unverified users
          unverifiedUser = user;
          showVerificationModal(user.email);
          document.getElementById(spinnerId).style.display = 'none';
          return; // Don't proceed further until verified
        }
      } else {
        // For other methods, proceed directly
        showReferralPopup(user.uid);
      }
    })
    .catch(error => {
      showToast("Error setting up your account. Please try again.", 'error');
      console.error("Error ensuring user exists:", error);
      document.getElementById(spinnerId).style.display = 'none';
    });
}

// Register and download app (from referral page)
function registerAndDownload() {
  const email = document.getElementById('downloadEmail').value;
  const password = document.getElementById('downloadPassword').value;
  const confirmPassword = document.getElementById('downloadConfirmPassword').value;
  const referralCode = document.getElementById('referralCode').value.trim().toUpperCase();
  
  // Input validation
  if (!email || !password || !confirmPassword) {
    showToast("Please fill in all required fields", 'error');
    return;
  }
  
  if (!validateEmail(email)) {
    showToast("Please enter a valid email address", 'error');
    return;
  }
  
  if (!validatePassword(password)) {
    showToast("Password must be at least 8 characters with uppercase, lowercase and a number", 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showToast("Passwords don't match!", 'error');
    return;
  }
  
  // Show loading spinner
  document.getElementById('downloadSpinner').style.display = 'block';
  
  auth.createUserWithEmailAndPassword(email, password)
    .then(result => {
      // Send verification email
      return result.user.sendEmailVerification()
        .then(() => {
          // Prepare user data
          const userData = {
            email: email,
            referralCodeUsed: referralCode || null,
            emailVerified: false,
            createdAt: firebase.database.ServerValue.TIMESTAMP
          };
          
          // Save user data to database
          return database.ref('appusers/' + result.user.uid).set(userData)
            .then(() => {
              // Process referral if exists
              if (referralCode) {
                return processReferral(result.user.uid, referralCode);
              }
              return Promise.resolve();
            });
        });
    })
    .then(() => {
      document.getElementById('downloadSpinner').style.display = 'none';
      
      // Show download success
      document.getElementById('downloadAppForm').classList.remove('active');
      document.getElementById('downloadSuccess').style.display = 'block';
      
      showToast("Registration successful! Please verify your email.", 'success');
    })
    .catch(error => {
      document.getElementById('downloadSpinner').style.display = 'none';
      showToast(getErrorMessage(error), 'error');
    });
}

// Process referral code for download app registration
function processReferral(userId, referralCode) {
  return database.ref('referralCodes/' + referralCode).once('value')
    .then(snapshot => {
      if (snapshot.exists()) {
        const referrerId = snapshot.val();
        
        // Update both users' data
        const updates = {};
        
        // For the new user (referee)
        updates[`appusers/${userId}/referredBy`] = referrerId;
        updates[`appusers/${userId}/withdrawableBalance`] = 25;
        updates[`appusers/${userId}/totalBalance`] = 25;
        
        // For the referrer
        updates[`appusers/${referrerId}/referralEarnings`] = firebase.database.ServerValue.increment(25);
        updates[`appusers/${referrerId}/withdrawableBalance`] = firebase.database.ServerValue.increment(25);
        updates[`appusers/${referrerId}/totalBalance`] = firebase.database.ServerValue.increment(25);
        updates[`appusers/${referrerId}/Referrals/${userId}`] = {
          email: document.getElementById('downloadEmail').value,
          timestamp: firebase.database.ServerValue.TIMESTAMP
        };
        
        return database.ref().update(updates);
      }
      return Promise.resolve();
    });
}

// Auth state listener
auth.onAuthStateChanged(user => {
  if (user) {
    // Check if user is coming from login/signup (no localStorage yet)
    if (!localStorage.getItem('uid')) {
      redirectAfterLogin(user, "existing_session");
    }
  } else {
    document.querySelector(".auth-body").style.display = "block";
    document.getElementById("userInfo").style.display = "none";
  }
});

// Email/Password Sign Up
function signUp() {
  const email = document.getElementById("signupEmail").value;
  const password = document.getElementById("signupPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  
  // Input validation
  if (!email || !password || !confirmPassword) {
    showToast("Please fill in all fields", 'error');
    return;
  }
  
  if (!validateEmail(email)) {
    showToast("Please enter a valid email address", 'error');
    return;
  }
  
  if (!validatePassword(password)) {
    showToast("Password must be at least 8 characters with uppercase, lowercase and a number", 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    showToast("Passwords don't match!", 'error');
    return;
  }
  
  // Show loading spinner
  document.getElementById('signupSpinner').style.display = 'block';
  
  auth.createUserWithEmailAndPassword(email, password)
    .then(result => {
      // Send verification email
      return result.user.sendEmailVerification()
        .then(() => {
          // Store the unverified user
          unverifiedUser = result.user;
          showVerificationModal(email);
          document.getElementById('signupSpinner').style.display = 'none';
        });
    })
    .catch(error => {
      document.getElementById('signupSpinner').style.display = 'none';
      showToast(getErrorMessage(error), 'error');
    });
}

// Email/Password Sign In
function signIn() {
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;
  
  // Input validation
  if (!email || !password) {
    showToast("Please fill in all fields", 'error');
    return;
  }
  
  if (!validateEmail(email)) {
    showToast("Please enter a valid email address", 'error');
    return;
  }
  
  // Show loading spinner
  document.getElementById('loginSpinner').style.display = 'block';
  
  auth.signInWithEmailAndPassword(email, password)
    .then(result => {
      if (!result.user.emailVerified) {
        // User is not verified, show verification modal
        unverifiedUser = result.user;
        showVerificationModal(email);
        document.getElementById('loginSpinner').style.display = 'none';
      } else {
        // User is verified, proceed normally
        redirectAfterLogin(result.user, "email/password");
      }
    })
    .catch(error => {
      document.getElementById('loginSpinner').style.display = 'none';
      showToast(getErrorMessage(error), 'error');
    });
}

// Check if user is already logged in
if (localStorage.getItem('uid')) {
  window.location.href = REDIRECT_URL;
}