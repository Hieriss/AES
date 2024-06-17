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
    public partial class Decryptor : Form
    {
        [DllImport("E:\\Workspace\\AES\\AES_DLL\\x64\\Debug\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "Decrypt")]
        public static extern void Decrypt(string mode, string key_file, string iv_file, string ciphertext_file, string recovered_file);

        public Decryptor()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string mode = comboBox1.SelectedItem.ToString();
            string key_file = textBox1.Text;
            string iv_file = textBox2.Text;
            string ciphertext_file = textBox3.Text;
            string recovered_file = textBox4.Text;
            Decrypt(mode, key_file, iv_file, ciphertext_file, recovered_file);
            MessageBox.Show("Decrypted successfully!");

        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
