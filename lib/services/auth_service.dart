import 'package:firebase_auth/firebase_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'firestore_service.dart';

/// Service to handle Authentication logic
class AuthService {
  // Singleton instance
  static final AuthService _instance = AuthService._internal();
  factory AuthService() => _instance;
  AuthService._internal();

  final FirebaseAuth _auth = FirebaseAuth.instance;

  // Google Sign In instance (used only for mobile)
  final GoogleSignIn _googleSignIn = GoogleSignIn();

  /// Stream to listen to auth state changes
  Stream<User?> get authStateChanges => _auth.authStateChanges();

  /// Get current user
  User? get currentUser => _auth.currentUser;

  /// SIGN IN WITH GOOGLE
  Future<UserCredential?> signInWithGoogle() async {
    try {
      UserCredential userCredential;

      if (kIsWeb) {
        /// 🔵 WEB LOGIN
        GoogleAuthProvider googleProvider = GoogleAuthProvider();

        userCredential =
            await FirebaseAuth.instance.signInWithPopup(googleProvider);
      } else {
        /// 🔵 MOBILE LOGIN (Android / iOS)
        final GoogleSignInAccount? googleUser =
            await _googleSignIn.signIn();

        if (googleUser == null) {
          return null;
        }

        final GoogleSignInAuthentication googleAuth =
            await googleUser.authentication;

        final OAuthCredential credential =
            GoogleAuthProvider.credential(
          accessToken: googleAuth.accessToken,
          idToken: googleAuth.idToken,
        );

        userCredential =
            await _auth.signInWithCredential(credential);
      }

      /// SAVE USER PROFILE TO FIRESTORE
      if (userCredential.user != null) {
        await FirestoreService().createOrUpdateUserProfile(
          uid: userCredential.user!.uid,
          email: userCredential.user!.email ?? '',
          displayName: userCredential.user!.displayName,
          photoUrl: userCredential.user!.photoURL,
        );
      }

      return userCredential;
    } on FirebaseAuthException catch (e) {
      String message = 'Authentication failed.';

      switch (e.code) {
        case 'account-exists-with-different-credential':
          message = 'Account exists with a different sign-in method.';
          break;

        case 'invalid-credential':
          message = 'Invalid credentials provided.';
          break;

        case 'operation-not-allowed':
          message = 'Google sign-in is not enabled.';
          break;

        case 'user-disabled':
          message = 'This user has been disabled.';
          break;

        default:
          message = e.message ?? 'Authentication error';
      }

      print("FirebaseAuthException: $message");
      throw message;
    } catch (e) {
      print("Google Sign-In Error: $e");
      throw 'An unexpected error occurred. Please try again.';
    }
  }

  /// SIGN IN WITH EMAIL + PASSWORD
  Future<UserCredential?> signInWithEmailAndPassword(
      String email, String password) async {
    try {
      final userCredential =
          await _auth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );

      if (userCredential.user != null) {
        await FirestoreService().createOrUpdateUserProfile(
          uid: userCredential.user!.uid,
          email: userCredential.user!.email ?? '',
          displayName: userCredential.user!.displayName,
          photoUrl: userCredential.user!.photoURL,
        );
      }

      return userCredential;
    } on FirebaseAuthException catch (e) {
      throw _handleFirebaseAuthError(e);
    } catch (e) {
      throw 'An unexpected error occurred.';
    }
  }

  /// REGISTER WITH EMAIL + PASSWORD
  Future<UserCredential?> registerWithEmailAndPassword(
      String email, String password, String username) async {
    try {
      final userCredential =
          await _auth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );

      if (userCredential.user != null) {
        await userCredential.user!
            .updateDisplayName(username);

        await FirestoreService().createOrUpdateUserProfile(
          uid: userCredential.user!.uid,
          email: email,
          displayName: username,
        );
      }

      return userCredential;
    } on FirebaseAuthException catch (e) {
      throw _handleFirebaseAuthError(e);
    } catch (e) {
      throw 'An unexpected error occurred.';
    }
  }

  /// HANDLE FIREBASE AUTH ERRORS
  String _handleFirebaseAuthError(FirebaseAuthException e) {
    switch (e.code) {
      case 'email-already-in-use':
        return 'The email address is already in use.';

      case 'invalid-email':
        return 'The email address is invalid.';

      case 'operation-not-allowed':
        return 'Email/password accounts are not enabled.';

      case 'weak-password':
        return 'The password is too weak.';

      case 'user-disabled':
        return 'The user account has been disabled.';

      case 'user-not-found':
        return 'No user found with this email.';

      case 'wrong-password':
        return 'Wrong password provided.';

      default:
        return e.message ?? 'Authentication error.';
    }
  }

  /// SIGN OUT
  Future<void> signOut() async {
    try {
      if (!kIsWeb) {
        await _googleSignIn.signOut();
      }

      await _auth.signOut();
    } catch (e) {
      print("Error signing out: $e");
      throw 'Failed to sign out.';
    }
  }
}