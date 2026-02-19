import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true, 
    trim: true, 
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email'] 
  },
  password: { 
    type: String, 
    minlength: 6,
    required: true
  },
  name: { 
    type: String, 
    required: true, 
    trim: true 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  loginAttempts: { 
    type: Number, 
    default: 0 
  },
  lockUntil: Date,
  refreshToken: String,
  otp: {
    type: String,
    default: null
  },
  otpExpires: {
    type: Date,
    default: null
  }
}, { 
  timestamps: true 
});

userSchema.virtual('isLocked').get(function() { 
  return !!(this.lockUntil && this.lockUntil > Date.now()); 
});

userSchema.pre('save', async function(next) { 
  if (!this.isModified('password')) return next(); 
  try { 
    const salt = await bcrypt.genSalt(12); 
    this.password = await bcrypt.hash(this.password, salt); 
    next(); 
  } catch (error) { 
    next(error); 
  } 
});

userSchema.methods.comparePassword = async function(candidatePassword) { 
  if (this.isLocked) throw new Error('Account is temporarily locked due to too many failed login attempts'); 
  const isMatch = await bcrypt.compare(candidatePassword, this.password); 
  if (isMatch) { 
    if (this.loginAttempts > 0) { 
      this.loginAttempts = 0; 
      this.lockUntil = undefined; 
      await this.save(); 
    } 
    return true; 
  } else { 
    this.loginAttempts += 1; 
    if (this.loginAttempts >= 5) { 
      this.lockUntil = Date.now() + (30 * 60 * 1000); 
    } 
    await this.save(); 
    return false; 
  } 
};

userSchema.methods.generateTokens = function() { 
  const accessToken = jwt.sign({ 
    userId: this._id, 
    email: this.email, 
    name: this.name 
  }, process.env.JWT_SECRET, { 
    expiresIn: '15m' 
  }); 
  
  const refreshToken = jwt.sign({ 
    userId: this._id 
  }, process.env.JWT_REFRESH_SECRET, { 
    expiresIn: '7d' 
  }); 
  
  return { accessToken, refreshToken }; 
};

const User = mongoose.model('User', userSchema);
export default User;
