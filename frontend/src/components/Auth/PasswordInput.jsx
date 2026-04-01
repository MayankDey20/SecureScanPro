import React, { useState } from 'react';

const PasswordInput = ({ value, onChange, placeholder = "••••••••", required = true, id = "password", name = "password" }) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="password-input-wrapper" style={{ position: 'relative' }}>
      <input
        type={showPassword ? "text" : "password"}
        id={id}
        name={name}
        value={value}
        onChange={onChange}
        required={required}
        placeholder={placeholder}
        style={{ width: '100%', paddingRight: '40px' }}
      />
      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        style={{
          position: 'absolute',
          right: '10px',
          top: '50%',
          transform: 'translateY(-50%)',
          background: 'none',
          border: 'none',
          color: '#6c757d',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 0
        }}
        aria-label={showPassword ? "Hide password" : "Show password"}
      >
        {showPassword ? "Hide" : "Show"}
      </button>
    </div>
  );
};

export default PasswordInput;
