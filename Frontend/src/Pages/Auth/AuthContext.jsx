import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [username, setUsername] = useState('');

  useEffect(() => {
    const checkAuth = async () => {
      const token = Cookies.get('jwt');
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const response = await axios.get('http://localhost:3000/user', { withCredentials: true });
        setIsAuthenticated(true);
        setUsername(response.data.username);
      } catch (error) {
        setIsAuthenticated(false);
        setUsername('');
      }
      setLoading(false);
    };

    checkAuth();
  }, []);

  // const login = async (username, password) => {
  //   try {
  //     await axios.post('http://localhost:3000/login', { username, password }, { withCredentials: true });
  //     setIsAuthenticated(true);
  //     setUsername(username);
  //   } catch (error) {
  //     console.error(error.response.data.msg);
  //   }
  // };

  const login = async (username, password) => {
    try{
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'include'
      });
  
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.msg );
      }
  
      // await axios.post('http://localhost:3000/login', { username, password }, { withCredentials: true });
      // setIsAuthenticated(true);
      // setUsername(username);
  
    setIsAuthenticated(true);
    setUsername(username);
    return data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
  };

  const logout = async () => {
    await axios.post('http://localhost:3000/logout', {}, { withCredentials: true });
    setIsAuthenticated(false);
    setUsername('');
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, loading, username, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
