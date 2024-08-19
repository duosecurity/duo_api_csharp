/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
namespace duo_api_csharp.Classes
{
    public class DuoModelBase
    {
        /// <summary>
        /// This method reverts a derived class back to its base class discarding any information
        /// This is used when a API request is made with a Response model to a Request method. In this case
        /// Serialising the model will send parameters that the server is not expecting and will result in a 400
        /// In this case, we discard any data not part of the request model to ensure the request succeeds
        /// </summary>
        /// <param name="BaseType">The request model to reflect</param>
        /// <returns>The desired request model</returns>
        /// <exception cref="ArgumentException">If the Response model does not derive from the request model</exception>
        internal object GetBaseClass(Type BaseType)
        {
            if( GetType() == BaseType ) return this;
            if( !GetType().IsAssignableTo(BaseType) ) throw new ArgumentException("Object is not derived from BaseType");
            var newBaseClass = Activator.CreateInstance(BaseType);
            if( newBaseClass != null )
            {
                foreach( var Property in BaseType.GetProperties() )
                {
                    var getValue = Property.GetValue(this);
                    if( getValue != null ) Property.SetValue(newBaseClass, getValue);
                }
                
                return newBaseClass;
            }
            
            throw new ArgumentException("Failed to create class");
        }
    }
}