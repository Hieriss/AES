using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AES_GUI
{
    public partial class Form1 : Form
    {
        [DllImport("C:\\Windows\\SysWOW64\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "KeyGen")]
        public static extern void KeyGen(string key_length, string file_name);

        [DllImport("C:\\Windows\\SysWOW64\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "IVGen")]
        public static extern void IV(string iv_length, string file_name);

        [DllImport("C:\\Windows\\SysWOW64\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "Encrypt")]
        public static extern void Encrypt(string mode, string key_file, string iv_file, string plaintext_file, string ciphertext_file);

        [DllImport("C:\\Windows\\SysWOW64\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "Decrypt")]
        public static extern void Decrypt(string mode, string key_file, string iv_file, string ciphertext_file, string plaintext_file, string recovered_file);
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string key_length = comboBox1.SelectedItem.ToString();
            string file_name = textBox1.Text;
            KeyGen(key_length, file_name);
            MessageBox.Show("Key generated successfully!");
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            string iv_length = comboBox2.SelectedItem.ToString();
            string file_name = textBox2.Text;
            IV(iv_length, file_name);
            MessageBox.Show("IV generated successfully!");
        }

        private void button3_Click(object sender, EventArgs e)
        {
            string mode = comboBox3.SelectedItem.ToString();
            string key_file = textBox3.Text;
            string iv_file = textBox4.Text;
            string plaintext_file = textBox5.Text;
            string ciphertext_file = textBox6.Text;
            Encrypt(mode, key_file, iv_file, plaintext_file, ciphertext_file);
            MessageBox.Show("Plaintext encrypted successfully!");
        }

        private void button4_Click(object sender, EventArgs e)
        {
            string mode = comboBox4.SelectedItem.ToString();
            string key_file = textBox7.Text;
            string iv_file = textBox8.Text;
            string ciphertext_file = textBox9.Text;
            string plaintext_file = textBox10.Text;
            string recovered_file = textBox11.Text;
            Decrypt(mode, key_file, iv_file, ciphertext_file, plaintext_file, recovered_file);
            MessageBox.Show("Ciphertext decrypted successfully!");
        }

        private void button5_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
