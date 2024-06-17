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
    public partial class KeyGenerator : Form
    {
        [DllImport("E:\\Workspace\\AES\\AES_DLL\\x64\\Debug\\AES_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "KeyGen")]
        public static extern void KeyGen(string key_length, string file_name);

        public KeyGenerator()
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string key_length = comboBox1.SelectedItem.ToString();
            string file_name = textBox2.Text;
            if (key_length == "")
            {
                MessageBox.Show("Please select your iv length!");
            }
            if (file_name == "")
            {
                MessageBox.Show("Please enter your file name!");
            }
            KeyGen(key_length, file_name);
            MessageBox.Show("Key generated successfully!");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
            Menu menu = new Menu();
            menu.Show();
        }
    }
}
