package com.example.mynativeapplication

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView
import com.example.mynativeapplication.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
        binding.sampleText.text = stringFromJNI()

        // Initialize the counter value from JNI
        updateCounter()

        // Set click listeners for the buttons
        binding.btnIncrement.setOnClickListener {
            incrementCounter()
            updateCounter()
        }

        binding.btnDecrement.setOnClickListener {
            decrementCounter()
            updateCounter()
        }
    }

    private fun updateCounter() {
        val counter = getCounterFromJNI()
        binding.tvCounter.text = counter.toString()
    }

    /**
     * A native method that is implemented by the 'mynativeapplication' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String
    external fun getCounterFromJNI(): Int
    external fun incrementCounter()
    external fun decrementCounter()

    companion object {
        // Used to load the 'mynativeapplication' library on application startup.
        init {
            System.loadLibrary("mynativeapplication")
        }
    }
}