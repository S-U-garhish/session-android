package org.thoughtcrime.securesms

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import com.garhish.zillaf.BuildConfig
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DeviceModule {
    @Provides
    @Singleton
    fun provides() = BuildConfig.DEVICE
}
