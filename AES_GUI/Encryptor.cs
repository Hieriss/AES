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
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace AES_GUI
{
    public partial class Encryptor : Form
    {
        [DllImport("E:\\Workspace\\AES\\AES_DLL\\x64\\Debug\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "Encrypt")]
        public static extern void Encrypt(string mode, string key_file, string iv_file, string plaintext_file, string ciphertext_file);

        public Encryptor()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string mode = comboBox1.SelectedItem.ToString();
            string key_file = textBox2.Text;
            string iv_file = textBox1.Text;
            string plaintext_file = textBox3.Text;
            string ciphertext_file = textBox4.Text;
            Encrypt(mode, key_file, iv_file, plaintext_file, ciphertext_file);
            MessageBox.Show("Encrypted successfully!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
